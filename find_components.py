# Cluster functions into components -- the pieces of one algorithm or one
# library -- from the dominators of the call graph
#@author Clifton Wolfe
#@category Analysis
#
# A function that every path from the program's entry points must pass
# through to reach some set of other functions is the front door of a
# component, and those functions are its private parts. That is dominance on
# the call graph, and the dominator tree is a hierarchy of components. This
# script cuts it up, prints it, and can record it as a program tree, as
# function tags, as a DOT file, or in Ghidra's graph viewer.
#
# Functions called from everywhere -- printf, malloc, a logger -- are the
# usual spoiler, since in a statically linked binary or firmware image their
# implementation is reachable from every component. Names in
# component_utils.STANDARD_LIBRARY_NAMES are treated as "soft leaves" (kept,
# but their outgoing calls dropped) by default; add the binary's own shared
# helpers with soft=... and use "suggest" to find them.
#
# With a selection in the GUI, only the functions in it are clustered.
#
# Headless:
#   analyzeHeadless <proj> <name> -process <bin> -postScript find_components.py
#   ... -postScript find_components.py min=4 soft=log_error,alloc tree tag
#
# Arguments (all optional, any order):
#   min=N        smallest dominated subtree that counts as a component (default 2)
#   hubs=N       a function with N or more callers does not join groups
#   soft=a,b     extra soft leaves, by name; "re:^log_" for a pattern
#   ignore=a,b   drop these functions from the graph entirely
#   nostdlib     do not treat standard library names as soft leaves
#   externals    include imported functions as leaves
#   datarefs     a function pointer taken inside a body counts as a call
#   tables=N     function pointers in data a body refers to count as calls;
#                2 follows one more pointer hop (device -> ops struct)
#   mkfuncs      with tables=N or datarefs, create functions at table entries
#                and taken pointers that point at code Ghidra made no
#                function of (modifies the program)
#   roots=a,b    keep only functions reachable from these ("entry" for the
#                program's marked entry points); drops dead archive code
#   post         cluster on the post-dominator tree (what funnels into what)
#   suggest      list functions with many callers that could be soft leaves
#   tree         create a program tree "Components" mirroring the clustering
#   tag          tag each function COMPONENT_<root>
#   graph        show the component graph in Ghidra's graph viewer (GUI only)
#   dot=path     write the component graph as Graphviz DOT
#   out=path     write the report to a file instead of the console
#   noshared     leave the undominated functions out of the report
#   nogroups     leave the groups out of the report
#   names=N      show at most N names per line

from __main__ import *

import re

from ghidra_api import component_utils as cu

import logging

log = logging.getLogger(__file__)
if not log.handlers:
    log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


def parse_args(args):
    options = {"min_size": 2, "soft": [], "ignore": [], "stdlib": True,
               "externals": False, "datarefs": False, "post": False,
               "suggest": False, "tree": False, "tag": False, "graph": False,
               "dot": None, "out": None, "shared": True, "groups": True,
               "names": None, "hubs": None, "tables": 0, "roots": None,
               "mkfuncs": False}
    for arg in args:
        arg = str(arg)
        if arg in ("externals", "datarefs", "post", "suggest", "tree", "tag",
                   "graph", "mkfuncs"):
            options[arg] = True
        elif arg == "nostdlib":
            options["stdlib"] = False
        elif arg == "noshared":
            options["shared"] = False
        elif arg == "nogroups":
            options["groups"] = False
        elif arg.startswith("min="):
            options["min_size"] = int(arg.split("=", 1)[1], 0)
        elif arg.startswith("names="):
            options["names"] = int(arg.split("=", 1)[1], 0)
        elif arg.startswith("hubs="):
            options["hubs"] = int(arg.split("=", 1)[1], 0)
        elif arg.startswith("tables="):
            options["tables"] = int(arg.split("=", 1)[1], 0)
        elif arg.startswith("roots="):
            value = arg.split("=", 1)[1]
            options["roots"] = (cu.ENTRY_ROOTS if value == cu.ENTRY_ROOTS
                                else [r for r in value.split(",") if r])
        elif arg.startswith("soft=") or arg.startswith("ignore="):
            key, value = arg.split("=", 1)
            for item in value.split(","):
                item = item.strip()
                if not item:
                    continue
                if item.startswith("re:"):
                    options[key].append(re.compile(item[3:]))
                else:
                    options[key].append(item)
        elif arg.startswith("dot=") or arg.startswith("out="):
            key, value = arg.split("=", 1)
            options[key] = value
        else:
            raise ValueError("unrecognised argument %r" % arg)
    return options


def selected_functions():
    """Functions in the current selection, or None when there is none."""
    selection = currentSelection
    if selection is None or selection.isEmpty():
        return None
    funcs = []
    for func in currentProgram.getFunctionManager().getFunctions(True):
        if selection.intersects(func.getBody()):
            funcs.append(func)
    return funcs


def show_graph(clustering):
    """Hand the component graph to the tool's graph display, if there is one."""
    tool = state.getTool()
    if tool is None:
        log.warning("no tool: the graph viewer needs the GUI")
        return
    from ghidra.app.services import GraphDisplayBroker
    from ghidra.service.graph import EmptyGraphType, GraphDisplayOptions
    broker = tool.getService(GraphDisplayBroker)
    if broker is None:
        log.warning("no graph display service is available")
        return
    display = broker.getDefaultGraphDisplay(False, monitor)
    display.setGraph(cu.component_graph(clustering),
                     GraphDisplayOptions(EmptyGraphType()), "Components", False,
                     monitor)


def main():
    options = parse_args(getScriptArgs())
    soft = list(options["soft"])
    if options["stdlib"]:
        soft.extend(cu.STANDARD_LIBRARY_NAMES)

    if options["mkfuncs"] and not (options["tables"] or options["datarefs"]):
        log.warning("mkfuncs does nothing without tables=N or datarefs")

    call_graph = cu.build_call_graph(
        program=currentProgram, soft_leaves=soft, ignored=options["ignore"],
        functions=selected_functions(), include_externals=options["externals"],
        include_data_refs=options["datarefs"], table_depth=options["tables"],
        create_table_functions=options["mkfuncs"], roots=options["roots"],
        monitor=monitor)
    log.info("call graph: %d functions, %d soft leaves, %d unreachable dropped, "
             "%d created from tables", len(call_graph),
             len(call_graph.soft_leaves()), len(call_graph.unreachable),
             len(call_graph.created))

    tree = (cu.post_dominator_tree(call_graph, monitor) if options["post"]
            else cu.dominator_tree(call_graph, monitor))
    clustering = cu.find_components(call_graph, min_size=options["min_size"],
                                    tree=tree, hub_callers=options["hubs"])

    lines = [cu.format_report(clustering, show_shared=options["shared"],
                              show_groups=options["groups"],
                              max_names=options["names"])]
    if options["suggest"]:
        lines.append("")
        lines.append("soft leaf candidates (callers, components calling):")
        for func, callers, spread in cu.suggest_soft_leaves(call_graph, tree=tree):
            lines.append("  %-40s %4d %4d" % (func.getName(), callers, spread))
    report = "\n".join(lines)
    if options["out"]:
        with open(options["out"], "w") as handle:
            handle.write(report + "\n")
        log.info("report written to %s", options["out"])
    else:
        print(report)

    if options["dot"]:
        cu.write_dot(clustering, options["dot"])
        log.info("component graph written to %s", options["dot"])
    if options["tree"]:
        cu.create_program_tree(clustering, "Components", currentProgram)
        log.info("program tree 'Components' created")
    if options["tag"]:
        tagged = cu.tag_components(clustering)
        log.info("%d tags added", len(tagged))
    if options["graph"]:
        show_graph(clustering)


if __name__ == "__main__":
    main()
