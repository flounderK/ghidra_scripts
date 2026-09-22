"""Tests for ghidra_api.component_utils against the api_test_cases fixture.

The fixture's shape (see the comment above alg_a_run in api_test_cases.c):

    main -> alg_a_run -> alg_a_step -> shared_helper -> shared_leaf
                         alg_a_step -> log_msg -> format_msg -> shared_leaf
    main -> alg_b_run -> alg_b_step -> shared_helper, log_msg
            alg_b_run -> alg_b_extra
    main -> log_msg
    main -> top_caller -> middle_caller -> leaf
    ring_a <-> ring_b, called by nothing
    add_op, mul_op: only ever referenced as function pointers
"""

import os
import re

from ghidra_api._compat import resolve_program
from ghidra.graph import GraphAlgorithms

from ghidra_api import component_utils as cu
from ghidra_test_support import get_function

FIXTURE = ("main", "alg_a_run", "alg_a_step", "alg_b_run", "alg_b_step",
           "alg_b_extra", "shared_helper", "shared_leaf", "log_msg",
           "format_msg", "ring_a", "ring_b", "top_caller", "middle_caller",
           "leaf", "add_op", "mul_op", "countdown", "init_globals",
           "dispatch", "dispatch_via_struct", "sum_inner_array")


class Context(object):
    def __init__(self):
        self.program = resolve_program(None)
        for name in FIXTURE:
            setattr(self, name, get_function(self.program, name))
        self.cg = cu.build_call_graph(program=self.program)
        self.tree = cu.dominator_tree(self.cg)
        self.clustering = cu.find_components(self.cg)


def setup_module():
    return Context()


def names(funcs):
    return sorted(f.getName() for f in funcs)


def same(a, b):
    if a is None or b is None:
        return a is None and b is None
    return cu.vertex_id(a) == cu.vertex_id(b)


def test_fixture_functions_present(t, ctx):
    for name in FIXTURE:
        t.not_none("fixture has %s" % name, getattr(ctx, name))


# --- the call graph ---------------------------------------------------------

def test_graph_has_one_source_and_one_sink(t, ctx):
    sources = [v.getId() for v in GraphAlgorithms.getSources(ctx.cg.graph)]
    sinks = [v.getId() for v in GraphAlgorithms.getSinks(ctx.cg.graph)]
    t.equal("the synthetic root is the only source", sources, [cu.ROOT_ID])
    t.equal("the synthetic sink is the only sink", sinks, [cu.SINK_ID])
    t.check("the graph holds every fixture function",
            all(ctx.cg.contains(getattr(ctx, n)) for n in FIXTURE))


def test_callees_and_callers(t, ctx):
    t.equal("alg_a_step calls log_msg and shared_helper",
            names(ctx.cg.callees(ctx.alg_a_step)), ["log_msg", "shared_helper"])
    t.equal("shared_helper is called from both algorithms",
            names(ctx.cg.callers(ctx.shared_helper)), ["alg_a_step", "alg_b_step"])
    t.equal("log_msg is called from main and both algorithms",
            names(ctx.cg.callers(ctx.log_msg)), ["alg_a_step", "alg_b_step", "main"])
    t.equal("a leaf calls nothing", ctx.cg.callees(ctx.shared_leaf), [])


def test_thunks_and_externals_left_out_by_default(t, ctx):
    funcs = ctx.cg.functions()
    t.check("no thunk is a vertex", not any(f.isThunk() for f in funcs))
    t.check("no external function is a vertex", not any(f.isExternal() for f in funcs))
    with_ext = cu.build_call_graph(program=ctx.program, include_externals=True)
    ext_callees = [f for f in with_ext.callees(ctx.main) if f.isExternal()]
    t.check("with include_externals main calls an external function",
            len(ext_callees) > 0)
    t.contains("the external printf is reached through its PLT thunk",
               names(ext_callees), "printf")


def test_entry_points(t, ctx):
    entries = names(ctx.cg.entry_points())
    t.contains("main is an entry point", entries, "main")
    t.contains("a function only taken by pointer is an entry point", entries, "add_op")
    t.equal("one member of the unreachable cycle is an entry point",
            sorted(n for n in entries if n.startswith("ring_")), ["ring_a"])
    t.check("a function with callers is not an entry point", "leaf" not in entries)


def test_exit_points(t, ctx):
    exits = names(ctx.cg.exit_points())
    t.contains("a leaf is an exit point", exits, "shared_leaf")
    t.equal("one member of the cycle nothing leaves is an exit point",
            sorted(n for n in exits if n.startswith("ring_")), ["ring_a"])


def test_data_refs_as_edges(t, ctx):
    cg = cu.build_call_graph(program=ctx.program, include_data_refs=True)
    t.contains("main 'calls' the function whose pointer it takes",
               names(cg.callees(ctx.main)), "add_op")
    t.check("that function is no longer an entry point",
            "add_op" not in names(cg.entry_points()))


def test_pointer_tables_as_edges(t, ctx):
    t.check("without table following the dispatcher calls nothing",
            "add_op" not in names(ctx.cg.callees(ctx.dispatch)))
    one = cu.build_call_graph(program=ctx.program, table_depth=1)
    t.equal("a table the body indexes yields its targets",
            names(one.callees(ctx.dispatch)), ["add_op", "mul_op", "sub_op"])
    two = cu.build_call_graph(program=ctx.program, table_depth=2)
    t.equal("two hops do", names(two.callees(ctx.dispatch_via_struct)),
            ["add_op", "mul_op", "sub_op"])
    t.check("the table targets are no longer entry points",
            "add_op" not in names(two.entry_points()))
    tree = cu.dominator_tree(two)
    t.check("and are dominated by main, having two dispatchers",
            same(tree.idom(ctx.add_op), ctx.main))
    from ghidra_api import call_ref_utils as cru
    g_ops = ctx.program.getSymbolTable().getGlobalSymbols("g_ops")[0].getAddress()
    t.equal("a raw scan of the struct alone finds no functions",
            cru.get_function_pointers_in_data(g_ops, ctx.program, depth=1), [])
    g_name = ctx.program.getSymbolTable().getGlobalSymbols("g_name")[0].getAddress()
    t.equal("a string is not scanned as a table",
            cru.get_function_pointers_in_data(g_name, ctx.program, depth=1), [])
    t.equal("following its pointer one hop finds the table",
            names(cru.get_function_pointers_in_data(g_ops, ctx.program, depth=2)),
            ["add_op", "mul_op", "sub_op"])


def test_create_functions_at_table_targets(t, ctx):
    from ghidra.program.model.symbol import SourceType
    sub_op = get_function(ctx.program, "sub_op")
    entry = sub_op.getEntryPoint()
    funcman = ctx.program.getFunctionManager()
    funcman.removeFunction(entry)
    t.equal("sub_op is gone", funcman.getFunctionAt(entry), None)
    try:
        without = cu.build_call_graph(program=ctx.program, table_depth=1)
        t.equal("a table entry with no function is not a callee",
                names(without.callees(ctx.dispatch)), ["add_op", "mul_op"])
        cg = cu.build_call_graph(program=ctx.program, table_depth=1,
                                 create_table_functions=True)
        made = funcman.getFunctionAt(entry)
        t.not_none("the entry gets a function created", made)
        t.equal("it is reported as created",
                [str(f.getEntryPoint()) for f in cg.created], [str(entry)])
        t.check("it is a vertex", made is not None and cg.contains(made))
        t.check("and a callee of the dispatcher",
                made is not None and str(entry) in
                [cu.vertex_id(f) for f in cg.callees(ctx.dispatch)])
        inside = ctx.sum_inner_array.getEntryPoint().add(4)
        t.check("code inside an existing function is never made a function",
                funcman.getFunctionContaining(inside) is not None
                and funcman.getFunctionAt(inside) is None)
    finally:
        made = funcman.getFunctionAt(entry)
        if made is None:
            from ghidra.app.cmd.function import CreateFunctionCmd
            CreateFunctionCmd(entry).applyTo(ctx.program)
            made = funcman.getFunctionAt(entry)
        if made is not None and made.getName() != "sub_op":
            made.setName("sub_op", SourceType.USER_DEFINED)
        # the shared context still holds the deleted Function object
        ctx.cg = cu.build_call_graph(program=ctx.program)
        ctx.tree = cu.dominator_tree(ctx.cg)
        ctx.clustering = cu.find_components(ctx.cg)


def test_roots_drop_unreachable_functions(t, ctx):
    cg = cu.build_call_graph(program=ctx.program, roots=["main"])
    dropped = names(cg.unreachable)
    t.check("the unreferenced cycle is dropped", "ring_a" in dropped and "ring_b" in dropped)
    t.check("functions only taken by pointer are dropped", "add_op" in dropped)
    t.check("main's callees stay", cg.contains(ctx.leaf) and cg.contains(ctx.alg_a_step))
    t.equal("main is the only entry point", names(cg.entry_points()), ["main"])
    t.check("the report says how many were dropped",
            "unreachable from the roots dropped" in cu.format_report(cu.find_components(cg)))
    with_refs = cu.build_call_graph(program=ctx.program, roots=["main"],
                                    include_data_refs=True)
    t.check("with data refs the pointer targets are reachable", with_refs.contains(ctx.add_op))
    entry = cu.build_call_graph(program=ctx.program, roots=cu.ENTRY_ROOTS,
                                include_data_refs=True)
    t.check("'entry' resolves to the program's entry points and reaches main",
            entry.contains(ctx.main) and len(entry.unreachable) > 0)
    t.equal("no roots means nothing is dropped", ctx.cg.unreachable, [])
    t.raises("roots that match nothing are an error rather than an empty graph",
             ValueError, cu.build_call_graph, program=ctx.program,
             roots=["no_such_function"])


def test_restricting_the_function_set(t, ctx):
    cg = cu.build_call_graph(program=ctx.program,
                             functions=[ctx.alg_a_run, ctx.alg_a_step, ctx.shared_helper])
    t.equal("only the listed functions are vertices", len(cg), 3)
    t.equal("calls out of the set are dropped",
            names(cg.callees(ctx.alg_a_step)), ["shared_helper"])


def test_match_functions(t, ctx):
    funcs = ctx.cg.functions()
    t.equal("a name matches exactly",
            names(cu.match_functions("shared_helper", funcs)), ["shared_helper"])
    t.equal("leading underscores are ignored",
            names(cu.match_functions(["__shared_helper"], funcs)), ["shared_helper"])
    t.equal("a Function matches itself",
            names(cu.match_functions(ctx.leaf, funcs)), ["leaf"])
    t.equal("a pattern matches every name it finds",
            names(cu.match_functions(re.compile("^shared_"), funcs)),
            ["shared_helper", "shared_leaf"])
    t.equal("None matches nothing", cu.match_functions(None, funcs), [])


def test_graph_of_only_a_cycle_has_no_natural_sink(t, ctx):
    cg = cu.build_call_graph(program=ctx.program, functions=[ctx.ring_a, ctx.ring_b])
    t.equal("both functions are vertices", len(cg), 2)
    t.equal("the cycle's entry is wired to the root", names(cg.entry_points()), ["ring_a"])
    t.equal("the cycle's exit is wired to the sink", names(cg.exit_points()), ["ring_a"])
    tree = cu.dominator_tree(cg)
    t.check("ring_b is dominated by ring_a", same(tree.idom(ctx.ring_b), ctx.ring_a))
    ptree = cu.post_dominator_tree(cg)
    t.check("post-dominance builds on a graph with no real sink",
            ptree.contains(ctx.ring_a) and ptree.contains(ctx.ring_b))
    cl = cu.find_components(cg)
    t.equal("the cycle is one component", [c.name for c in cl], ["ring_a"])


def test_empty_and_singleton_graphs(t, ctx):
    empty = cu.build_call_graph(program=ctx.program, functions=[])
    t.equal("an empty set gives an empty graph", len(empty), 0)
    t.equal("with nothing to cluster", len(cu.find_components(empty)), 0)
    t.equal("and no post-dominators to speak of",
            cu.post_dominator_tree(empty).roots(), [])
    single = cu.build_call_graph(program=ctx.program, functions=[ctx.leaf])
    t.equal("a lone function is its own entry and exit",
            (names(single.entry_points()), names(single.exit_points())),
            (["leaf"], ["leaf"]))
    cl = cu.find_components(single)
    t.check("it lands in the shared bucket", cl.component_of(ctx.leaf) is cl.top)
    t.equal("the report still renders", cu.format_report(cl).count("leaf"), 1)


def test_thunk_in_restricted_set_is_resolved(t, ctx):
    thunks = [f for f in ctx.program.getFunctionManager().getFunctions(True)
              if f.isThunk() and f.getThunkedFunction(True) is not None
              and not f.getThunkedFunction(True).isExternal()]
    if not thunks:
        t.check("fixture has no internal thunk; nothing to check", True)
        return
    cg = cu.build_call_graph(program=ctx.program, functions=[thunks[0]])
    t.check("the thunk is replaced by its target",
            not any(f.isThunk() for f in cg.functions()))


def test_soft_leaf_with_restricted_set(t, ctx):
    cg = cu.build_call_graph(program=ctx.program, soft_leaves=["alg_a_step"],
                             functions=[ctx.alg_a_run, ctx.alg_a_step, ctx.shared_helper])
    t.equal("the soft leaf keeps its caller", names(cg.callers(ctx.alg_a_step)), ["alg_a_run"])
    t.equal("and loses its callee", cg.callees(ctx.alg_a_step), [])
    t.equal("the orphaned callee becomes an entry point",
            names(cg.entry_points()), ["alg_a_run", "shared_helper"])


def test_self_recursion_is_not_an_edge(t, ctx):
    t.check("countdown is in the graph", ctx.cg.contains(ctx.countdown))
    t.check("its self call is not an edge",
            "countdown" not in names(ctx.cg.callees(ctx.countdown)))
    t.check("so it is still a leaf for exit purposes",
            "countdown" in names(ctx.cg.exit_points()))


# --- dominators -------------------------------------------------------------

def test_immediate_dominators(t, ctx):
    tree = ctx.tree
    t.check("alg_a_step is only reached through alg_a_run",
            same(tree.idom(ctx.alg_a_step), ctx.alg_a_run))
    t.check("shared_helper has two callers so main is its idom",
            same(tree.idom(ctx.shared_helper), ctx.main))
    t.check("shared_leaf likewise", same(tree.idom(ctx.shared_leaf), ctx.main))
    t.check("format_msg is private to log_msg",
            same(tree.idom(ctx.format_msg), ctx.log_msg))
    t.check("log_msg is dominated by main", same(tree.idom(ctx.log_msg), ctx.main))
    t.check("alg_b_extra is private to alg_b_run",
            same(tree.idom(ctx.alg_b_extra), ctx.alg_b_run))
    t.check("leaf is private to middle_caller",
            same(tree.idom(ctx.leaf), ctx.middle_caller))
    t.equal("main has no dominator", tree.idom(ctx.main), None)


def test_dominator_chain(t, ctx):
    t.equal("dominators run from leaf up to main",
            [f.getName() for f in ctx.tree.dominators(ctx.leaf)],
            ["leaf", "middle_caller", "top_caller", "main"])
    t.equal("an entry point's chain is just itself",
            [f.getName() for f in ctx.tree.dominators(ctx.main)], ["main"])


def test_dominated_sets(t, ctx):
    t.equal("top_caller dominates its whole chain",
            names(ctx.tree.dominated(ctx.top_caller)),
            ["leaf", "middle_caller", "top_caller"])
    t.equal("alg_b_run dominates its private helpers only",
            names(ctx.tree.dominated(ctx.alg_b_run)),
            ["alg_b_extra", "alg_b_run", "alg_b_step"])
    t.equal("children are the immediately dominated",
            names(ctx.tree.children(ctx.alg_b_run)), ["alg_b_extra", "alg_b_step"])


def test_dominates_and_depth(t, ctx):
    tree = ctx.tree
    t.check("main dominates leaf", tree.dominates(ctx.main, ctx.leaf))
    t.check("a function dominates itself", tree.dominates(ctx.leaf, ctx.leaf))
    t.check("alg_a_run does not dominate the shared helper",
            not tree.dominates(ctx.alg_a_run, ctx.shared_helper))
    t.equal("an entry point has depth 1", tree.depth(ctx.main), 1)
    t.equal("leaf is four deep", tree.depth(ctx.leaf), 4)
    t.contains("main is a root of the tree", names(tree.roots()), "main")


def test_unreachable_cycle_is_in_the_tree(t, ctx):
    tree = ctx.tree
    t.check("ring_a is in the tree", tree.contains(ctx.ring_a))
    t.check("ring_b is in the tree", tree.contains(ctx.ring_b))
    t.equal("ring_a is the cycle's entry", tree.idom(ctx.ring_a), None)
    t.check("ring_b is dominated by ring_a", same(tree.idom(ctx.ring_b), ctx.ring_a))


# --- soft leaves and ignored functions --------------------------------------

def test_soft_leaf_keeps_vertex_and_drops_calls(t, ctx):
    cg = cu.build_call_graph(program=ctx.program, soft_leaves=["shared_helper"])
    t.check("the soft leaf is still a vertex", cg.contains(ctx.shared_helper))
    t.check("it is reported as a soft leaf", cg.is_soft_leaf(ctx.shared_helper))
    t.equal("it calls nothing", cg.callees(ctx.shared_helper), [])
    t.equal("it is still called", names(cg.callers(ctx.shared_helper)),
            ["alg_a_step", "alg_b_step"])
    t.equal("soft_leaves() lists it", names(cg.soft_leaves()), ["shared_helper"])
    tree = cu.dominator_tree(cg)
    t.check("shared_leaf is now private to format_msg",
            same(tree.idom(ctx.shared_leaf), ctx.format_msg))
    t.check("and so dominated by log_msg", tree.dominates(ctx.log_msg, ctx.shared_leaf))


def test_soft_leaf_isolates_its_implementation(t, ctx):
    cg = cu.build_call_graph(program=ctx.program, soft_leaves=["log_msg"])
    t.contains("the soft leaf's private helper becomes an entry point",
               names(cg.entry_points()), "format_msg")
    tree = cu.dominator_tree(cg)
    t.equal("it has no dominator", tree.idom(ctx.format_msg), None)
    t.equal("a helper shared with the rest of the program has none either",
            tree.idom(ctx.shared_leaf), None)


def test_ignored_function_is_removed(t, ctx):
    cg = cu.build_call_graph(program=ctx.program, ignored=[ctx.shared_helper])
    t.check("the ignored function is not a vertex", not cg.contains(ctx.shared_helper))
    t.check("it is reported as ignored", cg.is_ignored(ctx.shared_helper))
    t.equal("calls to it vanish", names(cg.callees(ctx.alg_a_step)), ["log_msg"])
    t.equal("its callee keeps only its other callers",
            names(cg.callers(ctx.shared_leaf)), ["format_msg"])
    t.check("and is now dominated by that caller",
            same(cu.dominator_tree(cg).idom(ctx.shared_leaf), ctx.format_msg))


# --- post-dominators --------------------------------------------------------

def test_post_dominators(t, ctx):
    ptree = cu.post_dominator_tree(ctx.cg)
    t.check("the tree is marked as post-dominance", ptree.post)
    t.check("alg_a_run only ever calls alg_a_step",
            same(ptree.idom(ctx.alg_a_run), ctx.alg_a_step))
    t.check("every path out of alg_a_step ends in shared_leaf",
            same(ptree.idom(ctx.alg_a_step), ctx.shared_leaf))
    t.check("alg_b_run has a path that bypasses shared_leaf",
            not ptree.dominates(ctx.shared_leaf, ctx.alg_b_run))
    t.check("top_caller funnels into middle_caller",
            same(ptree.idom(ctx.top_caller), ctx.middle_caller))
    t.equal("a leaf has no post-dominator", ptree.idom(ctx.shared_leaf), None)
    t.check("the cycle nothing leaves is in the tree",
            ptree.contains(ctx.ring_a) and ptree.contains(ctx.ring_b))
    t.equal("post-dominators of alg_a_run",
            [f.getName() for f in ptree.dominators(ctx.alg_a_run)],
            ["alg_a_run", "alg_a_step", "shared_leaf"])


def test_components_by_post_dominance(t, ctx):
    ptree = cu.post_dominator_tree(ctx.cg)
    clustering = cu.find_components(ctx.cg, tree=ptree)
    t.check("alg_a_run is clustered under what it funnels into",
            same(clustering.component_of(ctx.alg_a_run).root, ctx.alg_a_step))


# --- components -------------------------------------------------------------

def test_component_hierarchy(t, ctx):
    cl = ctx.clustering
    leaf_comp = cl.component_of(ctx.leaf)
    t.check("leaf belongs to middle_caller's component",
            same(leaf_comp.root, ctx.middle_caller))
    t.check("nested under top_caller's", same(leaf_comp.parent.root, ctx.top_caller))
    t.check("nested under main's", same(leaf_comp.parent.parent.root, ctx.main))
    t.check("whose parent is the shared bucket",
            leaf_comp.parent.parent.parent is cl.top)
    t.equal("depth counts from the bucket", leaf_comp.depth, 3)
    t.check("alg_a_step is in alg_a_run's component",
            same(cl.component_of(ctx.alg_a_step).root, ctx.alg_a_run))
    t.check("the shared helper lands in main's component",
            same(cl.component_of(ctx.shared_helper).root, ctx.main))
    t.check("a lone entry point lands in the shared bucket",
            cl.component_of(ctx.add_op) is cl.top)
    t.contains("shared() lists it", names(cl.shared()), "add_op")
    t.check("components are listed parents first",
            [c.name for c in cl].index("main") < [c.name for c in cl].index("top_caller"))
    t.equal("len counts the real components", len(cl), len(cl.components))


def test_component_contents(t, ctx):
    comp = ctx.clustering.component_of(ctx.top_caller)
    t.equal("the root is the first member", comp.members[0].getName(), "top_caller")
    t.equal("members exclude nested components", names(comp.members), ["top_caller"])
    t.equal("one nested component", [c.name for c in comp.children], ["middle_caller"])
    t.equal("the subtree is everything dominated",
            names(comp.subtree), ["leaf", "middle_caller", "top_caller"])
    t.equal("size counts the subtree", comp.size, 3)
    t.equal("units are the owned members and child roots",
            names(comp.units()), ["middle_caller"])
    t.equal("walk visits nested components",
            [c.name for c in comp.walk()], ["top_caller", "middle_caller"])


def test_min_size(t, ctx):
    cl = cu.find_components(ctx.cg, min_size=3)
    t.check("a two-function subtree no longer stands alone",
            same(cl.component_of(ctx.leaf).root, ctx.top_caller))
    t.check("alg_a_run's pair folds into main",
            same(cl.component_of(ctx.alg_a_step).root, ctx.main))
    t.check("alg_b_run's triple still stands",
            same(cl.component_of(ctx.alg_b_step).root, ctx.alg_b_run))
    t.equal("min_size is recorded", cl.min_size, 3)


def test_groups_join_units_that_call_each_other(t, ctx):
    main_comp = ctx.clustering.component_of(ctx.main)
    group = [g for g in main_comp.groups if "alg_a_run" in names(g)][0]
    for name in ("alg_b_run", "shared_helper", "shared_leaf", "log_msg"):
        t.contains("alg_a_run's group holds %s" % name, names(group), name)
    top_group = [g for g in main_comp.groups if "top_caller" in names(g)][0]
    t.equal("top_caller shares nothing and stands alone", names(top_group), ["top_caller"])


def test_groups_do_not_bind_through_soft_leaves(t, ctx):
    cg = cu.build_call_graph(program=ctx.program,
                             soft_leaves=["shared_helper", "log_msg"])
    cl = cu.find_components(cg)
    main_comp = cl.component_of(ctx.main)
    group = [g for g in main_comp.groups if "alg_a_run" in names(g)][0]
    t.equal("alg_a_run no longer joins alg_b_run", names(group), ["alg_a_run"])


def test_groups_do_not_bind_through_hubs(t, ctx):
    cl = cu.find_components(ctx.cg, hub_callers=2)
    t.equal("functions with enough callers are hubs",
            sorted(ctx.cg.function_by_id(h).getName() for h in cl.hubs),
            ["log_msg", "shared_helper", "shared_leaf"])
    t.equal("the threshold is recorded", cl.hub_callers, 2)
    main_comp = cl.component_of(ctx.main)
    group = [g for g in main_comp.groups if "alg_a_run" in names(g)][0]
    t.equal("alg_a_run no longer joins alg_b_run through the hubs",
            names(group), ["alg_a_run"])
    t.contains("the report mentions the hubs", cu.format_report(cl), "hubs at 2 callers: 3")
    t.equal("without a threshold there are no hubs", ctx.clustering.hubs, set())


def test_suggest_soft_leaves(t, ctx):
    suggested = cu.suggest_soft_leaves(ctx.cg, min_callers=2, tree=ctx.tree)
    by_name = dict((f.getName(), (callers, spread)) for f, callers, spread in suggested)
    t.contains("log_msg is suggested", by_name, "log_msg")
    t.contains("shared_helper is suggested", by_name, "shared_helper")
    t.check("a leaf is never suggested", "shared_leaf" not in by_name)
    t.equal("caller counts are right", by_name["log_msg"][0], 3)
    t.equal("all of log_msg's callers sit under main", by_name["log_msg"][1], 1)
    t.equal("most-called comes first", suggested[0][0].getName(), "log_msg")
    already = cu.build_call_graph(program=ctx.program, soft_leaves=["log_msg"])
    t.check("an existing soft leaf is not suggested again",
            "log_msg" not in [f.getName() for f, _, _ in
                              cu.suggest_soft_leaves(already, min_callers=2)])


# --- output -----------------------------------------------------------------

def test_format_report(t, ctx):
    text = cu.format_report(ctx.clustering)
    t.contains("the report names components", text, "alg_a_run @")
    t.contains("the report has the shared bucket", text, "<shared>")
    t.contains("the report lists groups", text, "group:")
    without = cu.format_report(ctx.clustering, show_shared=False, show_groups=False)
    t.check("shared and groups can be left out",
            "<shared>" not in without and "group:" not in without)
    short = cu.format_report(ctx.clustering, max_names=1)
    t.contains("long member lists are truncated", short, "more)")


def test_component_graph(t, ctx):
    graph = cu.component_graph(ctx.clustering)
    t.equal("one vertex per component plus the bucket",
            graph.getVertexCount(), len(ctx.clustering) + 1)
    main_v = graph.getVertex(cu.vertex_id(ctx.main))
    alg_v = graph.getVertex(cu.vertex_id(ctx.alg_a_run))
    t.not_none("main's component is a vertex", main_v)
    t.check("main's component calls into alg_a_run's",
            main_v is not None and alg_v is not None
            and graph.containsEdge(main_v, alg_v))
    attributed = ctx.cg.to_attributed_graph(clustering=ctx.clustering)
    t.equal("the attributed call graph has every function",
            attributed.getVertexCount(), len(ctx.cg))
    t.equal("vertices know their component",
            attributed.getVertex(cu.vertex_id(ctx.leaf)).getAttribute("Component"),
            "middle_caller")


def test_write_dot(t, ctx):
    path = os.path.join(os.environ.get("TMPDIR", "/tmp"), "ghidra_api_components.dot")
    cu.write_dot(ctx.clustering, path)
    with open(path) as handle:
        text = handle.read()
    os.remove(path)
    t.check("a digraph is written", text.startswith("digraph"))
    t.contains("components appear as nodes", text, "alg_a_run")
    t.contains("edges carry weights", text, "->")


def test_create_program_tree(t, ctx):
    tree_name = "Components (test)"
    listing = ctx.program.getListing()
    root = cu.create_program_tree(ctx.clustering, tree_name)
    try:
        t.not_none("the root module is returned", root)
        t.not_none("the tree exists", listing.getRootModule(tree_name))
        fragment = listing.getFragment(tree_name, ctx.leaf.getEntryPoint())
        t.not_none("leaf has a fragment", fragment)
        if fragment is not None:
            t.equal("named after the function", fragment.getName(), "leaf")
            parents = [m.getName() for m in fragment.getParents()]
            t.equal("inside middle_caller's module", parents, ["middle_caller"])
        shared = listing.getFragment(tree_name, ctx.add_op.getEntryPoint())
        t.check("a shared function sits in the shared module",
                shared is not None and
                [m.getName() for m in shared.getParents()] == ["shared"])
        again = cu.create_program_tree(ctx.clustering, tree_name)
        t.not_none("rebuilding replaces the tree", again)
        default_name = listing.getDefaultRootModule().getTreeName()
        t.raises("the program's default tree is never replaced", ValueError,
                 cu.create_program_tree, ctx.clustering, default_name)
        t.not_none("and is still there", listing.getRootModule(default_name))
    finally:
        listing.removeTree(tree_name)


def test_tag_components(t, ctx):
    tagged = cu.tag_components(ctx.clustering, prefix="CTEST_", shared_tag="CTEST_shared")
    t.contains("leaf is tagged with its component", tagged, "CTEST_middle_caller")
    t.equal("the tag lands on the function",
            sorted(tag.getName() for tag in ctx.leaf.getTags()
                   if tag.getName().startswith("CTEST_")),
            ["CTEST_middle_caller"])
    t.contains("shared functions get the shared tag", tagged, "CTEST_shared")
    t.equal("tag names are sanitised", cu.tag_name(ctx.clustering.top, "P_"), "P_shared")
