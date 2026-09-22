"""
Cluster a program's functions into components -- the groups that make up one
algorithm or one library -- from the dominators of its call graph.

The idea is simple: if every path from the program's entry points to a
function ``f`` runs through some function ``d``, then ``f`` is only ever
reached by way of ``d`` and belongs to whatever ``d`` is the front door of.
That is exactly dominance, so the dominator tree of the call graph *is* a
hierarchy of components: each function together with everything it dominates.
:func:`find_components` cuts that tree into a hierarchy of :class:`Component`
objects, and :class:`Clustering` gives the flat "which component is this
function in" view.

Two things get in the way in real binaries and both have knobs here:

* **Shared functions.** ``printf``, ``malloc``, a logging helper -- anything
  called from everywhere -- is dominated by nothing but the root, and in a
  statically linked binary or bare-metal firmware its own implementation
  (``vfprintf`` and friends) is reachable from every component and so belongs
  to none. Marking such a function a **soft leaf** keeps it in the graph but
  drops its outgoing calls, so its implementation falls out as a component of
  its own and no longer leaks into the callers'. Marking it **ignored**
  removes it from the graph entirely. :data:`STANDARD_LIBRARY_NAMES` is a
  starting list for the soft leaves, and :func:`suggest_soft_leaves` finds the
  ones a particular binary has.

* **Libraries with several entry points.** A library called through three
  different API functions has its shared internals dominated by the callers'
  common ancestor, not by any one API function, so pure dominance scatters it.
  Each component therefore also carries ``groups``: its directly owned
  sub-units, joined up by the calls between them, which puts the three API
  functions and their common internals back into one group.

Post-dominance is the same analysis run backwards -- "every path *out of* ``f``
runs through ``p``" -- and :func:`post_dominator_tree` gives that tree. It is
mostly useful once the ubiquitous leaves are ignored, since a call to
``memcpy`` is a path out that bypasses everything.

Everything is built on Ghidra's own graph machinery: the graph is a
``GDirectedGraph`` from ``GraphFactory``, the vertices are
``AttributedVertex`` objects (what Ghidra's graph viewer displays), and the
dominance comes from ``ChkDominanceAlgorithm``, the same code behind
``GraphAlgorithms.findDominanceTree`` and the program tree's "Dominance"
modularization.
"""

from ._compat import resolve_monitor, resolve_program
from .call_ref_utils import get_called_functions, resolve_thunk

from collections import defaultdict, deque

from ghidra.graph import DefaultGEdge, GraphAlgorithms, GraphFactory
from ghidra.graph.algo import ChkDominanceAlgorithm, ChkPostDominanceAlgorithm
from ghidra.service.graph import AttributedGraph, AttributedVertex, EmptyGraphType
from java.util import ArrayList

try:
    string_types = basestring  # Jython: names may arrive as unicode
except NameError:
    string_types = str


ROOT_ID = "<root>"
SINK_ID = "<sink>"

# Functions that are infrastructure rather than part of any one algorithm.
# Treating these as soft leaves keeps a static libc's internals from being
# threaded through every component that logs, allocates or copies. Matched
# with leading underscores stripped, so "_printf" and "__libc_malloc" count.
STANDARD_LIBRARY_NAMES = frozenset((
    # stdio
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "dprintf", "vdprintf", "asprintf", "vasprintf",
    "puts", "fputs", "putc", "putchar", "fputc", "fwrite", "fread", "fopen",
    "fclose", "fflush", "fseek", "ftell", "rewind", "fgets", "fgetc", "getc",
    "getchar", "ungetc", "scanf", "fscanf", "sscanf", "vscanf", "vfscanf",
    "vsscanf", "perror", "setvbuf", "setbuf", "tmpfile", "remove", "rename",
    "feof", "ferror", "clearerr", "fileno", "fdopen", "freopen",
    # memory
    "malloc", "calloc", "realloc", "free", "reallocarray", "posix_memalign",
    "aligned_alloc", "memalign", "valloc", "cfree", "libc_malloc",
    "libc_free", "libc_calloc", "libc_realloc", "brk", "sbrk", "mmap",
    "munmap", "mprotect", "mremap",
    # string / memory primitives
    "memcpy", "memmove", "memset", "memcmp", "memchr", "memrchr", "mempcpy",
    "bzero", "bcopy", "strlen", "strnlen", "strcpy", "strncpy", "stpcpy",
    "stpncpy", "strcat", "strncat", "strcmp", "strncmp", "strcasecmp",
    "strncasecmp", "strchr", "strrchr", "strstr", "strcasestr", "strdup",
    "strndup", "strtok", "strtok_r", "strsep", "strspn", "strcspn",
    "strpbrk", "strerror", "strerror_r", "strcoll", "strxfrm", "strlcpy",
    "strlcat", "strchrnul", "wcslen", "wcscpy", "wcscmp", "wmemcpy",
    "wmemset",
    # conversion
    "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll",
    "strtoull", "strtod", "strtof", "strtold", "itoa", "utoa", "ltoa",
    "toupper", "tolower", "isalpha", "isdigit", "isalnum", "isspace",
    "isprint", "isupper", "islower", "isxdigit", "ispunct", "iscntrl",
    # process / error handling
    "exit", "_exit", "Exit", "abort", "atexit", "on_exit", "assert",
    "assert_fail", "assert_perror_fail", "stack_chk_fail", "errno_location",
    "raise", "signal", "sigaction", "longjmp", "setjmp", "siglongjmp",
    "sigsetjmp", "getenv", "setenv", "putenv", "unsetenv", "system",
    "getpid", "getppid", "kill", "sleep", "usleep", "nanosleep",
    # io / os
    "open", "close", "read", "write", "lseek", "ioctl", "fcntl", "dup",
    "dup2", "pipe", "select", "poll", "stat", "fstat", "lstat", "access",
    "unlink", "mkdir", "rmdir", "opendir", "readdir", "closedir", "chdir",
    "getcwd", "socket", "connect", "bind", "listen", "accept", "send",
    "recv", "sendto", "recvfrom", "setsockopt", "getsockopt", "shutdown",
    "gethostbyname", "getaddrinfo", "freeaddrinfo", "inet_addr", "inet_ntoa",
    "htons", "htonl", "ntohs", "ntohl",
    # time
    "time", "clock", "gettimeofday", "clock_gettime", "localtime",
    "localtime_r", "gmtime", "gmtime_r", "mktime", "strftime", "difftime",
    # threads / locking
    "pthread_create", "pthread_join", "pthread_detach", "pthread_exit",
    "pthread_self", "pthread_mutex_lock", "pthread_mutex_unlock",
    "pthread_mutex_init", "pthread_mutex_destroy", "pthread_cond_wait",
    "pthread_cond_signal", "pthread_cond_broadcast", "pthread_once",
    "pthread_key_create", "pthread_getspecific", "pthread_setspecific",
    # misc libc
    "qsort", "bsearch", "rand", "srand", "random", "srandom", "abs", "labs",
    "div", "ldiv", "syslog", "openlog", "closelog", "vsyslog", "getopt",
    "getopt_long", "dlopen", "dlsym", "dlclose", "dlerror",
    # libm
    "sin", "cos", "tan", "asin", "acos", "atan", "atan2", "sinh", "cosh",
    "tanh", "exp", "log", "log10", "log2", "pow", "sqrt", "cbrt", "ceil",
    "floor", "round", "trunc", "fmod", "fabs", "ldexp", "frexp", "modf",
    "sinf", "cosf", "tanf", "expf", "logf", "powf", "sqrtf", "fabsf",
    "floorf", "ceilf", "roundf", "fmodf",
    # gcc runtime / soft float
    "udivsi3", "divsi3", "umodsi3", "modsi3", "udivdi3", "divdi3", "umoddi3",
    "moddi3", "muldi3", "ashldi3", "ashrdi3", "lshrdi3", "udivmoddi4",
    "aeabi_uidiv", "aeabi_idiv", "aeabi_uidivmod", "aeabi_idivmod",
    "aeabi_uldivmod", "aeabi_ldivmod", "aeabi_memcpy", "aeabi_memset",
    "aeabi_memclr", "aeabi_memmove", "aeabi_fadd", "aeabi_fsub",
    "aeabi_fmul", "aeabi_fdiv", "aeabi_dadd", "aeabi_dsub", "aeabi_dmul",
    "aeabi_ddiv", "aeabi_f2d", "aeabi_d2f", "aeabi_i2f", "aeabi_f2iz",
    "aeabi_i2d", "aeabi_d2iz", "aeabi_fcmpeq", "aeabi_fcmplt", "aeabi_dcmpeq",
    "aeabi_dcmplt", "addsf3", "subsf3", "mulsf3", "divsf3", "adddf3",
    "subdf3", "muldf3", "divdf3", "floatsisf", "floatsidf", "fixsfsi",
    "fixdfsi", "extendsfdf2", "truncdfsf2", "eqsf2", "nesf2", "gtsf2",
    "gesf2", "ltsf2", "lesf2", "eqdf2", "nedf2", "gtdf2", "gedf2", "ltdf2",
    "ledf2", "clzsi2", "ctzsi2", "popcountsi2", "cxa_atexit", "cxa_finalize",
    "cxa_throw", "cxa_begin_catch", "cxa_end_catch", "cxa_guard_acquire",
    "cxa_guard_release", "cxa_pure_virtual", "gxx_personality_v0",
    "Unwind_Resume", "Unwind_RaiseException",
))


# --- the call graph ---------------------------------------------------------

def vertex_id(func):
    """The vertex id used for @func: its entry point, as text."""
    return str(func.getEntryPoint())


def _bare_name(name):
    return name.lstrip("_")


def match_functions(specs, functions):
    """The members of @functions that any of @specs selects.

    A spec is a Function (matched by entry point), a name (matched exactly,
    or with leading underscores stripped from both sides so ``printf`` also
    finds ``_printf`` and ``__printf``), or a compiled regular expression
    (``search``-ed against the bare name). @specs may also be a single spec.
    """
    if specs is None:
        return []
    if (isinstance(specs, string_types) or hasattr(specs, "getEntryPoint")
            or hasattr(specs, "search")):
        specs = [specs]
    ids = set()
    names = set()
    patterns = []
    for spec in specs:
        if hasattr(spec, "getEntryPoint"):
            ids.add(vertex_id(resolve_thunk(spec)))
        elif hasattr(spec, "search"):
            patterns.append(spec)
        else:
            names.add(_bare_name(str(spec)))
    matched = []
    for func in functions:
        name = func.getName()
        bare = _bare_name(name)
        if (vertex_id(func) in ids or bare in names
                or any(p.search(name) for p in patterns)):
            matched.append(func)
    return matched


class FunctionCallGraph(object):
    """A program's call graph as a Ghidra ``GDirectedGraph`` over functions.

    Every function is an ``AttributedVertex`` whose id is its entry point and
    whose name is the function's name, so ``graph`` can be handed to anything
    in ``GraphAlgorithms``. Two synthetic vertices complete it: ``root``, with
    an edge to every entry point, and ``sink``, with an edge from every exit
    point, so the graph always has exactly one source and one sink -- which is
    what Ghidra's dominance algorithm needs, and what a program with
    unreferenced recursive functions (a cycle nothing enters, or nothing
    leaves) does not naturally have.

    Build one with :func:`build_call_graph`.
    """

    def __init__(self, program, graph, root, sink, functions_by_id,
                 vertices_by_id, soft_leaf_ids, ignored_ids, entry_ids,
                 exit_ids):
        self.program = program
        self.graph = graph
        self.root = root
        self.sink = sink
        self._functions = functions_by_id
        self._vertices = vertices_by_id
        self._soft_leaves = soft_leaf_ids
        self._ignored = ignored_ids
        self._entries = entry_ids
        self._exits = exit_ids
        self.unreachable = []
        self.created = []

    # --- vertex <-> function ---

    def vertex(self, func):
        """The vertex for @func, or None when it is not in the graph."""
        return self._vertices.get(vertex_id(func))

    def vertex_by_id(self, vid):
        return self._vertices.get(vid)

    def function(self, vertex):
        """The Function behind @vertex, or None for a synthetic vertex."""
        return self._functions.get(vertex.getId())

    def function_by_id(self, vid):
        return self._functions.get(vid)

    def is_synthetic(self, vertex):
        return vertex.getId() not in self._functions

    def contains(self, func):
        return vertex_id(func) in self._vertices

    def functions(self):
        """Every function in the graph, in address order."""
        return [self._functions[i] for i in sorted(self._functions)]

    def __len__(self):
        return len(self._functions)

    def __contains__(self, func):
        return self.contains(func)

    # --- edges ---

    def _neighbours(self, func, successors):
        vertex = self.vertex(func)
        if vertex is None:
            return []
        if successors:
            found = self.graph.getSuccessors(vertex)
        else:
            found = self.graph.getPredecessors(vertex)
        result = []
        for other in found:
            other_func = self.function(other)
            if other_func is not None:
                result.append(other_func)
        return sorted(result, key=vertex_id)

    def callees(self, func):
        """Functions @func calls, after soft-leaf and ignore handling."""
        return self._neighbours(func, True)

    def callers(self, func):
        return self._neighbours(func, False)

    def is_soft_leaf(self, func):
        return vertex_id(func) in self._soft_leaves

    def is_ignored(self, func):
        return vertex_id(func) in self._ignored

    def soft_leaves(self):
        return [self._functions[i] for i in sorted(self._soft_leaves)
                if i in self._functions]

    def entry_points(self):
        """Functions nothing calls, plus one function per unreachable cycle."""
        return [self._functions[i] for i in sorted(self._entries)]

    def exit_points(self):
        """Functions that call nothing, plus one function per cycle nothing
        leaves."""
        return [self._functions[i] for i in sorted(self._exits)]

    # --- export ---

    def to_attributed_graph(self, name="Call Graph", clustering=None):
        """A copy as an ``AttributedGraph`` for Ghidra's graph viewer or its
        exporters, without the synthetic vertices. With @clustering, each
        vertex carries a ``Component`` attribute naming its component."""
        out = AttributedGraph(name, EmptyGraphType())
        for vid in sorted(self._functions):
            vertex = self._vertices[vid]
            copy = out.addVertex(vid, vertex.getName())
            if clustering is not None:
                component = clustering.component_of(self._functions[vid])
                if component is not None:
                    copy.setAttribute("Component", component.name)
        for edge in self.graph.getEdges():
            start = edge.getStart().getId()
            end = edge.getEnd().getId()
            if start in self._functions and end in self._functions:
                out.addEdge(out.getVertex(start), out.getVertex(end))
        return out


def _java_list(items):
    result = ArrayList()
    for item in items:
        result.add(item)
    return result


def _frontier(graph, top_down):
    """The vertices a synthetic root (or sink) must be wired to so that every
    vertex is reachable from it (or can reach it).

    Top-down that is the sources plus one representative of each strongly
    connected component that nothing outside it enters -- a recursive pair
    nothing calls, say. Bottom-up it is the sinks plus one representative of
    each component that nothing leaves. This is ``GraphAlgorithms
    .getEntryPoints`` generalised to both directions; without it the
    dominance algorithm asserts on the vertices it cannot reach.
    """
    if top_down:
        seeds = set(GraphAlgorithms.getSources(graph))
        reached = set(GraphAlgorithms.getDescendants(graph, _java_list(seeds)))
    else:
        seeds = set(GraphAlgorithms.getSinks(graph))
        reached = set(GraphAlgorithms.getAncestors(graph, _java_list(seeds)))
    remaining = set(graph.getVertices()) - seeds - reached
    frontier = set(seeds)
    if not remaining:
        return frontier
    subgraph = GraphAlgorithms.createSubGraph(graph, _java_list(remaining))
    for component in GraphAlgorithms.getStronglyConnectedComponents(subgraph):
        members = set(component)
        outside = set()
        for vertex in members:
            if top_down:
                outside.update(graph.getPredecessors(vertex))
            else:
                outside.update(graph.getSuccessors(vertex))
        if outside <= members:
            frontier.add(min(members, key=lambda v: v.getId()))
    return frontier


ENTRY_ROOTS = "entry"


def program_entry_points(program):
    """The functions Ghidra marks as external entry points: the ELF or PE
    entry, exported functions, and whatever the loader flagged."""
    funcman = program.getFunctionManager()
    found = {}
    entries = program.getSymbolTable().getExternalEntryPointIterator()
    while entries.hasNext():
        func = funcman.getFunctionAt(entries.next())
        if func is not None:
            found.setdefault(vertex_id(func), func)
    return [found[i] for i in sorted(found)]


def build_call_graph(program=None, soft_leaves=(), ignored=(), functions=None,
                     include_externals=False, include_data_refs=False,
                     table_depth=0, create_table_functions=False, roots=None,
                     monitor=None):
    """Build the :class:`FunctionCallGraph` of @program.

    @soft_leaves and @ignored take anything :func:`match_functions` accepts:
    functions, names, or compiled patterns. A soft leaf stays in the graph
    with its outgoing calls removed; an ignored function is left out along
    with every call to or from it.

    @functions restricts the graph to those functions (thunks are resolved);
    by default every non-thunk, non-external function is a vertex. External
    functions -- imports -- are natural leaves and are left out unless
    @include_externals is set, since they say more about the loader than the
    program. @include_data_refs makes a function pointer taken inside a body
    count as a call to its target, which is how callbacks get registered.
    @table_depth makes the function pointers stored in data a body refers to
    count as calls (1), or those one pointer hop further (2): a dispatch
    table's targets are then owned by the function that indexes the table,
    and a driver's ops struct by the code that uses the device. Without it
    every function only reachable through a table is an entry point of its
    own, and a table-driven binary -- busybox, a firmware image -- has most
    of its code in the shared bucket. @create_table_functions goes one step
    further and makes functions of table entries that point at code Ghidra
    never made a function of, which is most of an applet table in a stripped
    binary; it changes the program, so the caller owns the transaction.

    @roots keeps only the functions reachable from the given ones (anything
    :func:`match_functions` accepts, or the string ``"entry"`` for the
    program's marked entry points). A statically linked archive drags in
    whole object files, so an application carries unreferenced API
    functions -- ``deflateParams``, say -- that are entry points in their
    own right and make every internal they touch look shared. The dropped
    functions are listed on the result as ``unreachable``.
    """
    program = resolve_program(program)
    monitor = resolve_monitor(monitor)

    if functions is None:
        candidates = [f for f in program.getFunctionManager().getFunctions(True)
                      if not f.isThunk() and not f.isExternal()]
    else:
        seen = {}
        for func in functions:
            func = resolve_thunk(func)
            if func is not None:
                seen.setdefault(vertex_id(func), func)
        candidates = [seen[i] for i in sorted(seen)]
    allowed = set(vertex_id(f) for f in candidates)

    soft_ids = set(vertex_id(f) for f in match_functions(soft_leaves, candidates))
    ignored_ids = set(vertex_id(f) for f in match_functions(ignored, candidates))

    graph = GraphFactory.createDirectedGraph()
    vertices = {}
    funcs = {}
    table_cache = {}

    def vertex_for(func):
        vid = vertex_id(func)
        vertex = vertices.get(vid)
        if vertex is None:
            vertex = AttributedVertex(vid, func.getName())
            vertices[vid] = vertex
            funcs[vid] = func
            graph.addVertex(vertex)
        return vertex

    pending = deque(candidates)
    created = []
    while pending:
        func = pending.popleft()
        monitor.checkCancelled()
        fid = vertex_id(func)
        if fid in ignored_ids:
            continue
        vertex = vertex_for(func)
        if fid in soft_ids:
            continue
        for callee in get_called_functions(
                func, program, include_data_refs=include_data_refs,
                table_depth=table_depth,
                create_table_functions=create_table_functions,
                _table_cache=table_cache):
            cid = vertex_id(callee)
            if cid == fid or cid in ignored_ids:
                continue
            if callee.isExternal():
                if not include_externals:
                    continue
            elif cid not in allowed:
                if functions is not None or not create_table_functions \
                        or callee.isThunk():
                    continue
                # a function created from a table entry: it is part of the
                # program now, so it gets vertices and callees of its own
                allowed.add(cid)
                created.append(callee)
                pending.append(callee)
            graph.addEdge(DefaultGEdge(vertex, vertex_for(callee)))

    unreachable = []
    if roots is not None:
        if isinstance(roots, string_types) and roots == ENTRY_ROOTS:
            root_funcs = program_entry_points(program)
        else:
            root_funcs = match_functions(roots, list(funcs.values()))
        pending = [vertices[vertex_id(f)] for f in root_funcs
                   if vertex_id(f) in vertices]
        if not pending:
            raise ValueError("no function in the graph matches roots=%r" % (roots,))
        keep = set()
        for vertex in pending:
            keep.add(vertex.getId())
        while pending:
            vertex = pending.pop()
            for successor in graph.getSuccessors(vertex):
                if successor.getId() not in keep:
                    keep.add(successor.getId())
                    pending.append(successor)
        for vid in sorted(vertices):
            if vid not in keep:
                unreachable.append(funcs[vid])
                graph.removeVertex(vertices[vid])
                del vertices[vid]
                del funcs[vid]

    entries = _frontier(graph, True)
    root = AttributedVertex(ROOT_ID, ROOT_ID)
    graph.addVertex(root)
    for vertex in entries:
        graph.addEdge(DefaultGEdge(root, vertex))

    exits = _frontier(graph, False)
    exits.discard(root)
    sink = AttributedVertex(SINK_ID, SINK_ID)
    graph.addVertex(sink)
    for vertex in exits:
        graph.addEdge(DefaultGEdge(vertex, sink))
    if not exits:
        # nothing at all in the graph: keep the one-source-one-sink invariant
        graph.addEdge(DefaultGEdge(root, sink))

    result = FunctionCallGraph(
        program, graph, root, sink, funcs, vertices, soft_ids, ignored_ids,
        set(v.getId() for v in entries), set(v.getId() for v in exits))
    result.unreachable = unreachable
    result.created = created
    return result


# --- dominance --------------------------------------------------------------

class DominanceTree(object):
    """The dominator (or post-dominator) tree of a :class:`FunctionCallGraph`.

    Built from ``ChkDominanceAlgorithm.getDominanceTree()`` and then read
    entirely from Python-side maps, so no query recurses in Java. Every
    function-facing method takes and returns Functions; the synthetic root
    and sink are ``None`` wherever they would appear.
    """

    def __init__(self, call_graph, algorithm, post):
        self.call_graph = call_graph
        self.post = post
        self.algorithm = algorithm
        self.tree = algorithm.getDominanceTree()
        self.root_id = SINK_ID if post else ROOT_ID
        self._idom = {}
        self._children = defaultdict(list)
        for edge in self.tree.getEdges():
            dom = edge.getStart().getId()
            sub = edge.getEnd().getId()
            self._idom[sub] = dom
            self._children[dom].append(sub)
        for children in self._children.values():
            children.sort()

    def _id(self, func):
        return vertex_id(func)

    def _func(self, vid):
        return self.call_graph.function_by_id(vid)

    def _funcs(self, vids):
        return [f for f in (self._func(v) for v in vids) if f is not None]

    def contains(self, func):
        vid = self._id(func)
        return vid in self._idom or vid == self.root_id

    def idom(self, func):
        """The immediate dominator of @func, or None when nothing but the
        synthetic root dominates it (or it is not in the graph)."""
        return self._func(self._idom.get(self._id(func)))

    def children(self, func):
        """Functions @func immediately dominates."""
        return self._funcs(self._children.get(self._id(func), ()))

    def roots(self):
        """Functions with no dominator: children of the synthetic root."""
        return self._funcs(self._children.get(self.root_id, ()))

    def dominators(self, func):
        """@func and every function that dominates it, nearest first."""
        result = []
        vid = self._id(func)
        if vid not in self._idom:
            return result
        while vid is not None and vid != self.root_id:
            f = self._func(vid)
            if f is not None:
                result.append(f)
            vid = self._idom.get(vid)
        return result

    def dominated(self, func):
        """@func and every function it dominates."""
        return self._funcs(self._subtree_ids(self._id(func)))

    def _subtree_ids(self, start):
        if start not in self._idom and start != self.root_id:
            return []
        order = []
        pending = [start]
        while pending:
            vid = pending.pop()
            order.append(vid)
            pending.extend(reversed(self._children.get(vid, ())))
        return order

    def preorder_ids(self):
        return self._subtree_ids(self.root_id)

    def dominates(self, dominator, func):
        """Whether @dominator dominates @func (a function dominates itself)."""
        target = self._id(dominator)
        vid = self._id(func)
        if vid not in self._idom:
            return False
        while vid is not None:
            if vid == target:
                return True
            vid = self._idom.get(vid)
        return False

    def depth(self, func):
        """Distance from the synthetic root; 1 for an undominated function."""
        vid = self._id(func)
        if vid not in self._idom:
            return None
        depth = 0
        cursor = vid
        while cursor is not None and cursor != self.root_id:
            depth += 1
            cursor = self._idom.get(cursor)
        return depth

    def subtree_sizes(self):
        """{vertex id: number of functions in its dominated subtree}."""
        order = self.preorder_ids()
        sizes = {}
        functions = self.call_graph._functions
        for vid in reversed(order):
            total = 1 if vid in functions else 0
            for child in self._children.get(vid, ()):
                total += sizes[child]
            sizes[vid] = total
        return sizes


def dominator_tree(call_graph, monitor=None):
    """The dominator tree: ``idom(f)`` is the nearest function every path
    from an entry point to ``f`` passes through."""
    monitor = resolve_monitor(monitor)
    return DominanceTree(call_graph,
                         ChkDominanceAlgorithm(call_graph.graph, monitor), False)


def post_dominator_tree(call_graph, monitor=None):
    """The post-dominator tree: ``idom(f)`` is the nearest function every
    call chain out of ``f`` passes through before bottoming out."""
    monitor = resolve_monitor(monitor)
    return DominanceTree(call_graph,
                         ChkPostDominanceAlgorithm(call_graph.graph, monitor), True)


# --- components -------------------------------------------------------------

class Component(object):
    """A cluster of functions: a dominator and everything only reachable
    through it, minus the nested components that were cut out of it.

    ``root`` is the dominating function, or None for the top-level bucket of
    functions that no single function dominates -- the shared ones.
    ``members`` are the functions placed directly in this component (the root
    first); ``children`` are the nested components; ``subtree`` is everything
    the root dominates, nested components included. ``groups`` partitions the
    directly owned units -- the non-root members and the child roots -- by
    the calls between them (and their subtrees), with calls into soft leaves
    not counting as a link; a library reached through several entry points
    shows up as one group even though dominance splits it.
    """

    def __init__(self, root, parent=None):
        self.root = root
        self.parent = parent
        self.depth = 0 if parent is None else parent.depth + 1
        self.members = [] if root is None else [root]
        self.children = []
        self.groups = []

    @property
    def name(self):
        return "<shared>" if self.root is None else self.root.getName()

    @property
    def id(self):
        return ROOT_ID if self.root is None else vertex_id(self.root)

    @property
    def subtree(self):
        result = list(self.members)
        for child in self.children:
            result.extend(child.subtree)
        return result

    @property
    def size(self):
        return len(self.subtree)

    def units(self):
        """The non-root members and the child roots: what the root owns."""
        own = self.members if self.root is None else self.members[1:]
        return own + [c.root for c in self.children]

    def walk(self):
        """This component and every nested one, depth first."""
        yield self
        for child in self.children:
            for nested in child.walk():
                yield nested

    def __repr__(self):
        return "Component(%s, %d members, %d children)" % (
            self.name, len(self.members), len(self.children))


class Clustering(object):
    """The result of :func:`find_components`.

    ``top`` is the shared bucket; ``components`` lists every real component,
    parents before children; ``component_of`` answers where a function went.
    """

    def __init__(self, call_graph, tree, top, min_size, hub_callers=None,
                 hubs=()):
        self.call_graph = call_graph
        self.tree = tree
        self.top = top
        self.min_size = min_size
        self.hub_callers = hub_callers
        self.hubs = set(hubs)
        self.components = [c for c in top.walk() if c.root is not None]
        self._by_id = {}
        for component in top.walk():
            for func in component.members:
                self._by_id[vertex_id(func)] = component

    def component_of(self, func):
        return self._by_id.get(vertex_id(func))

    def shared(self):
        """Functions no single function dominates."""
        return list(self.top.members)

    def __iter__(self):
        return iter(self.components)

    def __len__(self):
        return len(self.components)


def find_components(call_graph, min_size=2, tree=None, hub_callers=None,
                    monitor=None):
    """Cut the dominator tree of @call_graph into components.

    A function whose dominated subtree holds at least @min_size functions
    (itself included) becomes the root of a component; every other function
    joins the component of its nearest such dominator, or the shared bucket
    when there is none. With the default of 2 every function that has even
    one private helper is a component; raise it to see only the larger units.

    Pass a :func:`post_dominator_tree` as @tree to cluster by what functions
    funnel into instead of what they are reached through.

    @hub_callers keeps omnipresent functions from binding groups: a unit
    with at least that many callers (a stripped binary's own ``xmalloc`` or
    ``bb_error_msg``) is treated like a soft leaf when the groups are formed.
    Without it, a binary whose helpers are shared everywhere collapses its
    shared bucket into one group.
    """
    if tree is None:
        tree = dominator_tree(call_graph, monitor)
    sizes = tree.subtree_sizes()
    functions = call_graph._functions
    top = Component(None)
    owner = {tree.root_id: top}
    for vid in tree.preorder_ids()[1:]:
        func = functions.get(vid)
        parent = owner[tree._idom[vid]]
        if func is None:
            owner[vid] = parent
            continue
        if sizes[vid] >= min_size:
            component = Component(func, parent)
            parent.children.append(component)
            owner[vid] = component
        else:
            parent.members.append(func)
            owner[vid] = parent
    hubs = set()
    if hub_callers is not None:
        for func in call_graph.functions():
            if len(call_graph.callers(func)) >= hub_callers:
                hubs.add(vertex_id(func))
    clustering = Clustering(call_graph, tree, top, min_size, hub_callers, hubs)
    for component in top.walk():
        component.groups = _group_units(component, clustering, hubs)
    return clustering


def _group_units(component, clustering, hubs=()):
    """Partition a component's units by the calls between them. Calls into
    soft leaves and into @hubs (vertex ids) do not join units."""
    units = component.units()
    if not units:
        return []
    unit_of = {}
    for unit in units:
        unit_of[vertex_id(unit)] = vertex_id(unit)
    for child in component.children:
        cid = vertex_id(child.root)
        for func in child.subtree:
            unit_of[vertex_id(func)] = cid

    parent = dict((vertex_id(u), vertex_id(u)) for u in units)

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    call_graph = clustering.call_graph
    for fid, uid in list(unit_of.items()):
        func = call_graph.function_by_id(fid)
        for callee in call_graph.callees(func):
            cid = vertex_id(callee)
            other = unit_of.get(cid)
            if other is None or other == uid:
                continue
            if call_graph.is_soft_leaf(callee) or cid in hubs:
                continue
            parent[find(uid)] = find(other)

    buckets = defaultdict(list)
    for unit in units:
        buckets[find(vertex_id(unit))].append(unit)
    groups = list(buckets.values())
    for group in groups:
        group.sort(key=lambda f: f.getName())
    groups.sort(key=lambda g: (-len(g), g[0].getName()))
    return groups


def suggest_soft_leaves(call_graph, min_callers=5, tree=None):
    """Functions worth marking as soft leaves, most-called first.

    A candidate has at least @min_callers callers and calls something itself
    -- a leaf gains nothing from being soft. Each entry is
    ``(function, caller count, component count)`` where the last is how many
    distinct dominator-tree roots the callers sit under when @tree is given,
    or 0 when it is not.
    """
    results = []
    for func in call_graph.functions():
        if call_graph.is_soft_leaf(func):
            continue
        callers = call_graph.callers(func)
        if len(callers) < min_callers or not call_graph.callees(func):
            continue
        spread = 0
        if tree is not None:
            tops = set()
            for caller in callers:
                chain = tree.dominators(caller)
                tops.add(vertex_id(chain[-1]) if chain else None)
            spread = len(tops)
        results.append((func, len(callers), spread))
    results.sort(key=lambda r: (-r[1], r[0].getName()))
    return results


# --- output -----------------------------------------------------------------

def component_graph(clustering, name="Components"):
    """An ``AttributedGraph`` with one vertex per component and an edge for
    each pair of components with calls between them, weighted by call count.
    Handy for Ghidra's graph viewer or :func:`write_dot`."""
    graph = AttributedGraph(name, EmptyGraphType())
    for component in clustering.top.walk():
        vertex = graph.addVertex(component.id, "%s [%d]" % (component.name,
                                                           len(component.members)))
        vertex.setAttribute("Functions", str(len(component.members)))
        vertex.setAttribute("Subtree", str(component.size))
        if component.parent is not None:
            vertex.setAttribute("Parent", component.parent.name)
    call_graph = clustering.call_graph
    for func in call_graph.functions():
        source = clustering.component_of(func)
        for callee in call_graph.callees(func):
            target = clustering.component_of(callee)
            if source is None or target is None or source is target:
                continue
            graph.addEdge(graph.getVertex(source.id), graph.getVertex(target.id))
    return graph


def _dot_quote(text):
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_dot(clustering, path, name="components"):
    """Write the component graph to @path in Graphviz DOT."""
    graph = component_graph(clustering)
    lines = ["digraph %s {" % _dot_quote(name), "  node [shape=box];"]
    for vertex in sorted(graph.vertexSet(), key=lambda v: v.getId()):
        lines.append("  %s [label=%s];" % (_dot_quote(vertex.getId()),
                                           _dot_quote(vertex.getName())))
    for edge in graph.edgeSet():
        weight = edge.getAttribute(AttributedGraph.WEIGHT) or "1"
        lines.append("  %s -> %s [label=%s];" % (
            _dot_quote(graph.getEdgeSource(edge).getId()),
            _dot_quote(graph.getEdgeTarget(edge).getId()), _dot_quote(weight)))
    lines.append("}")
    with open(path, "w") as out:
        out.write("\n".join(lines) + "\n")


def format_report(clustering, show_shared=True, show_groups=True, max_names=None):
    """A readable, indented listing of the clustering."""
    lines = []
    call_graph = clustering.call_graph
    lines.append("%d functions%s, %d components (min_size=%d%s)%s" % (
        len(call_graph),
        "" if not call_graph.unreachable
        else " (%d unreachable from the roots dropped)" % len(call_graph.unreachable),
        len(clustering), clustering.min_size,
        "" if clustering.hub_callers is None
        else ", hubs at %d callers: %d" % (clustering.hub_callers,
                                           len(clustering.hubs)),
        ", post-dominance" if clustering.tree.post else ""))
    soft = call_graph.soft_leaves()
    if soft:
        lines.append("soft leaves: %s" % ", ".join(f.getName() for f in soft))

    def names(funcs):
        funcs = sorted(funcs, key=lambda f: f.getName())
        shown = funcs if max_names is None else funcs[:max_names]
        text = ", ".join(f.getName() for f in shown)
        if len(shown) < len(funcs):
            text += ", ... (%d more)" % (len(funcs) - len(shown))
        return text

    def emit(component):
        indent = "  " * component.depth
        if component.root is None:
            if not show_shared:
                for child in component.children:
                    emit(child)
                return
            lines.append("%s<shared> %d function(s) no single function dominates" % (
                indent, len(component.members)))
            members = component.members
        else:
            lines.append("%s%s @ %s: %d function(s), %d nested" % (
                indent, component.name, vertex_id(component.root),
                component.size, len(component.children)))
            members = component.members[1:]
        if members:
            lines.append("%s  members: %s" % (indent, names(members)))
        if show_groups:
            multi = [g for g in component.groups if len(g) > 1]
            for group in multi:
                lines.append("%s  group: %s" % (indent, names(group)))
        for child in component.children:
            emit(child)

    emit(clustering.top)
    return "\n".join(lines)


def _unique_name(base, taken):
    name = base
    index = 1
    while name in taken:
        index += 1
        name = "%s(%d)" % (base, index)
    taken.add(name)
    return name


def create_program_tree(clustering, tree_name="Components", program=None):
    """Mirror the clustering as a program tree, one module per component and
    one fragment per function, replacing any tree of that name except the
    program's default tree, which is refused. External functions have no
    addresses a fragment can hold and are skipped. The caller owns the
    transaction. Returns the root module."""
    program = resolve_program(clustering.call_graph.program if program is None
                              else program)
    listing = program.getListing()
    default_tree = listing.getDefaultRootModule()
    if default_tree is not None and default_tree.getTreeName() == tree_name:
        raise ValueError("refusing to replace the program's default tree %r"
                         % tree_name)
    if listing.getRootModule(tree_name) is not None:
        listing.removeTree(tree_name)
    root = listing.createRootModule(tree_name)
    taken = set([tree_name])

    def place(func, module):
        if func.isExternal():
            return
        fragment = module.createFragment(_unique_name(func.getName(), taken))
        for address_range in func.getBody().getAddressRanges():
            fragment.move(address_range.getMinAddress(),
                          address_range.getMaxAddress())

    def fill(component, module):
        for func in component.members:
            place(func, module)
        for child in component.children:
            fill(child, module.createModule(_unique_name(child.name, taken)))

    top = clustering.top
    if top.members:
        shared = root.createModule(_unique_name("shared", taken))
        for func in top.members:
            place(func, shared)
    for child in top.children:
        fill(child, root.createModule(_unique_name(child.name, taken)))
    return root


_TAG_SAFE = ("abcdefghijklmnopqrstuvwxyz"
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def tag_name(component, prefix="COMPONENT_"):
    text = "".join(c if c in _TAG_SAFE else "_" for c in component.name)
    return prefix + text.strip("_")


def tag_components(clustering, prefix="COMPONENT_", shared_tag="COMPONENT_shared"):
    """Add a function tag naming its component to every function. The caller
    owns the transaction. Pass ``shared_tag=None`` to leave the shared
    functions untagged. Returns {tag name: functions tagged}."""
    tagged = defaultdict(list)
    for component in clustering.top.walk():
        name = shared_tag if component.root is None else tag_name(component, prefix)
        if name is None:
            continue
        for func in component.members:
            func.addTag(name)
            tagged[name].append(func)
    return dict(tagged)
