# Ghidra Scripts


## API
Ghidra's API is still pretty minimal, so a lot of these scripts just add another layer of API on-top of ghidra's existing `FlatProgramAPI` for functions that I have found to be useful but that aren't easily accessible or that require a bit more setup than I feel that they should. In general, I will try to keep a naming scheme of `*_utils` to mirror the strategy present in a lot of ghidra's code of making `static` `*Utilities` classes, which are generally the most usable and useful parts of ghidra's existing API.

### call_ref_utils.py
Utilities for working will call references, mostly for following the call graph, finding callsites through thunks, finding all callsites for a function name, or creating new indirect call references

### byte_search_utils.py
Wrapper around ghidra's built-in memory search service (`ghidra.features.base.memsearch`, what the Search -> Memory dialog drives). Supports exact byte sequences, per-byte masks, and java regular expressions over bytes, with the same alignment and code-unit filters the GUI offers. `find_any` searches for many patterns in as few passes over memory as possible, which matters because re-reading memory, not matching, is what makes a large scan slow.

Note that a pattern longer than 100 bytes is refused rather than silently unreliable: the searcher only lets a match run 100 bytes past the end of a search chunk, so a longer pattern gets missed whenever it straddles a chunk boundary. Search a prefix and confirm the rest with `read_memory`.

### component_utils.py
Clusters a program's functions into components -- the groups that make up one algorithm or one library -- from the dominators of its call graph. If every path from the program's entry points to `f` runs through `d`, then `f` is only ever reached by way of `d` and belongs to whatever `d` is the front door of; the dominator tree of the call graph is therefore a hierarchy of components, and `find_components` cuts it into one. `post_dominator_tree` is the same analysis backwards (what every call chain out of `f` funnels into), and `find_components` clusters on either tree.

The call graph is a Ghidra `GDirectedGraph` over `AttributedVertex` objects (the type Ghidra's graph viewer displays), and the dominance comes from Ghidra's own `ChkDominanceAlgorithm`, the code behind `GraphAlgorithms.findDominanceTree` and the program tree's "Dominance" modularization. A synthetic root and sink are wired to the entry and exit points, including unreferenced recursive cycles, which that algorithm otherwise asserts on.

Two knobs deal with what real binaries do to this:

* **Soft leaves and ignored functions.** A function called from everywhere -- `printf`, `malloc`, a logger -- is dominated by nothing, and in a statically linked binary or bare-metal firmware image its implementation is reachable from every component and so belongs to none. A *soft leaf* stays in the graph with its outgoing calls dropped, so its implementation falls out as a component of its own; an *ignored* function is removed entirely. `STANDARD_LIBRARY_NAMES` is a starting list, matched with leading underscores stripped, and `suggest_soft_leaves` finds the binary's own.
* **Groups.** A library reached through several API functions has its shared internals dominated by the callers' common ancestor, not by any one API function, so pure dominance scatters it. Each component also carries `groups`: its directly owned sub-units joined up by the calls between them (calls into soft leaves do not count), which puts such a library back into one group. In a stripped static binary nothing matches the name list, and its own omnipresent helpers -- `xmalloc`, the error reporter -- bind everything into one group; `hub_callers=N` makes any function with that many callers non-binding, which is the classic "omnipresent node" rule from software clustering.

Table-driven code is the other thing dominance cannot see on its own: a function only ever reached through a dispatch table, an applet table or a driver's ops struct has no caller, so it is an entry point in its own right and its helpers end up shared. `table_depth` follows a reference from a function body into the data it points at, reads the pointer-sized words there and counts the ones that are function entry points as calls (with 2, a pointer to further data is followed one hop, which is how a device struct reaches its ops struct). The table does not need to be typed; a raw `undefined1[160]` works. In a stripped binary most table targets were never made functions at all (busybox's applet table names 263 entry points and Ghidra had functions for 86 of them), so `create_table_functions` makes a function at any table entry pointing at code outside every existing function. A switch's jump table points inside a function and is left alone.

Statically linked archives bring in whole object files, so an application carries unreferenced API functions that are entry points in their own right and make every internal they touch look shared. `roots` keeps only what is reachable from the functions you name (or from the program's marked entry points with `"entry"`), and lists what it dropped as `unreachable`. Combine it with `include_data_refs` so a `main` passed to `__libc_start_main` by pointer is still reached.

The result can be written out as an indented report (`format_report`), a program tree with a module per component (`create_program_tree`), function tags (`tag_components`), a Graphviz file of the component graph (`write_dot`) or an `AttributedGraph` for the graph viewer (`component_graph`).

### const_encoding_utils.py
Turns a logical sequence of constants into the byte sequences it can actually appear as in a binary: big and little endian, packed as u8/u16/u32/u64, wide words split into narrower elements (including the word-swapped layouts where the element order disagrees with the byte order), byte tables widened to u32 the way a C `int[]` table lands, and sequences stored backwards the way bignum limbs usually are. Layouts that produce identical bytes are collapsed and reported once. No ghidra dependency.

### const_scan_utils.py
Scans a program's memory for the constants in `crypto_const_utils`, in every layout `const_encoding_utils` produces. Searches a bounded prefix of each layout and then confirms the full sequence by reading memory at the hit, which both filters coincidences and reports how much of a table is really present.

### crypto_const_utils.py
The cryptographic, checksum, hash and algorithmic constants themselves, and the arithmetic that produces them. Most are derived rather than transcribed -- the SHA-2 tables from roots of primes, MD5's from `sin`, Blowfish's from the digits of pi, the AES S-box from the GF(2^8) inverse, CRC tables from their polynomials -- so a typo becomes a broken derivation rather than a signature that silently never matches. The ones with no closed form (DES's permutation tables, the MD2 and SM4 S-boxes, curve parameters) are written out, and the test suite checks each against a structural property it must have. No ghidra dependency, so it can be imported and tested without a program open.

### datatype_utils.py
Utilities for finding datatypes, finding datatypes that meet certain constraints, finding datatype usage within other datatypes, and finding field usage across the program as a whole.

### decomp_utils.py
Utilities for interacting with ghidra's decompiler and `PCODE` as well as making associations between disassembled instructions, pcode operations, and decompiled pseudo-c. Also includes some utilities related to forward/backward slicing.

### java_reflection_utils.py
Utilities for interacting with `java`'s reflection API through python

### loopfinder.py
Utilities for interacting with loops.

### pointer_utils.py
Utilities for searching for embedded addresses or address ranges. Current implementation may be broken on current ghidra

### function_signature_utils.py
Utilities related to working with and modifying function signatures

### register_utils.py
utilities for working with registers


## Useful automation and analysis scripts

### addr_search.py
Work flow script to search for an embedded address. If ghidra doesn't find a reference to a function and you think it is getting called, run this script on the address to find potential references to it. May be broken with current version of ghidra.

### find_unk_periphs.py
Constant analysis script to search for all of the constant values used in the binary, or a subsection of it. this outputs a map of what all of the constant values would look like as a memory map, along with a small number of stats on number of accesses and whether the access was an execution.
You can then create a new memory region in the memory window to view all of the new cross references.
Regions that are very close to 0 or regions that are very close to 0xffffffff or 0xffffffffffffffff can often be ignored as they are frequently just normal integers that are not used as pointers.
**NOTE: this will create false positives**

### coverage_highlight.py
Highlight the listing view from addresses listed in a file. Decent for viewing coverage from fuzzing.

### find_and_ops.py
Example script for finding every instance of a specific pcode op in raw (not refined) pcode.

### crypto_const_scan.py
Scan a program for cryptographic, checksum, hash and algorithmic constants: SHA-2 round tables, AES S-boxes and T-tables, CRC tables, Blowfish's digits of pi, DES permutations, curve parameters, base64 alphabets and so on. Identifies an algorithm even when every symbol has been stripped.

Each constant is searched for in every layout it could plausibly have, which is the point of the script -- the same table looks quite different in a 32-bit big-endian firmware image and an x86-64 shared object, and an S-box declared `int[256]` in C lands as u32s rather than bytes. Every hit reports the layout it was read as and how many words of the constant actually verified, so a partially embedded table is distinguishable from a coincidence.

Run it with no arguments to print what it finds. Optional arguments, in any order:

| argument | effect |
| --- | --- |
| `bookmark` | add a note bookmark in the "Crypto Constants" category at each match |
| `label` | add a primary label at each match, leaving any user-defined symbol alone |
| `complete` | only report constants that verified in full |
| `scalars` | also report single-word constants such as the TEA delta. Noisy: four bytes is far too little to search memory for, and these mostly appear as instruction immediates anyway, where `large_scalar_search.py` and `find_unk_periphs.py` are the better tools |
| `category=a,b` | restrict to some of `hash`, `cipher`, `checksum`, `curve`, `encoding`, `algorithmic` |
| `name=text` | restrict to signatures whose name contains `text` |
| `align=N` | only report matches at addresses that are a multiple of N |

For reference, scanning OpenSSL 3's `libcrypto.so.3` (4.4MB) takes about eight seconds and finds 40 constants, including the NIST P-256 field prime stored three different ways in the same binary.

### find_components.py
Cluster the program's functions into components with `component_utils` and print the hierarchy: each component's root, the functions only reachable through it, the nested components, and the groups of sub-units that call each other. Standard library names are soft leaves by default; add the binary's own shared helpers with `soft=` and use `suggest` to find them. With a selection in the GUI only the selected functions are clustered.

Run it with no arguments to print the report. Optional arguments, in any order:

| argument | effect |
| --- | --- |
| `min=N` | smallest dominated subtree that counts as a component (default 2) |
| `hubs=N` | a function with N or more callers does not join groups |
| `soft=a,b` | extra soft leaves by name; `re:^log_` for a pattern |
| `ignore=a,b` | drop these functions from the graph entirely |
| `nostdlib` | do not treat standard library names as soft leaves |
| `externals` | include imported functions as leaves |
| `datarefs` | a function pointer taken inside a body counts as a call |
| `tables=N` | function pointers in data a body refers to count as calls; 2 follows one more pointer hop |
| `mkfuncs` | with `tables=N` or `datarefs`, create functions at table entries and taken pointers that point at code Ghidra made no function of (modifies the program) |
| `roots=a,b` | keep only functions reachable from these (`entry` for the program's marked entry points) |
| `post` | cluster on the post-dominator tree instead |
| `suggest` | list functions with many callers that could be soft leaves |
| `tree` | create a program tree "Components" mirroring the clustering |
| `tag` | tag each function `COMPONENT_<root>` |
| `graph` | show the component graph in Ghidra's graph viewer (GUI only) |
| `dot=path` | write the component graph as Graphviz DOT |
| `out=path` | write the report to a file |
| `noshared`, `nogroups`, `names=N` | trim the report |

### find_str_constant.py
sometimes does magic with identifying string functions by looking for specific constant values

### find_unknown_pointers.py
Exactly what it is named, but to clarify, identifies possible missing cross references to every currently defined memory region. Can produce false positives.

### name_periph_related_funcs.py
finds references to all of the different defined memory regions in code and attempts to change function names to more explicitly associate them with that memory region if accessing the memory region is all the function is actually doing

### print_funcs_by_refcount.py
print functions in order by the number of references to it there are. It is often useful to name the most called functions and fix up their parameters to speed up reversing of the whole binary.

### source_file_grouping.py
Auto rename functions if they don't have a name yet and have a reference to a `.c` filepath in them, as would commonly be seen passed into assert functions.

### tag_callback_registration.py
identify functions that look like they are registering callback functions

### type_pointers_to_data.py
Identify already defined data in memory that can be represented as a pointer to a currently established memory region. If it can and there is a defined data type at the pointed to address, change the type of the pointer appropriately. Also automatically creates a "pointer offset" typedef if the pointer is to the middle of a struct, which is somewhat common.

This is very useful for architectures like arm that frequently utilize a "constant pool" for each function because ghidra will not automatically change the types of pointers in constant pools.

## Running under Jython or PyGhidra
Everything here runs under both of Ghidra's python runtimes: `Jython` (bundled through Ghidra 11.x, an installable extension from 12 on) and `PyGhidra`, which is real CPython talking to the JVM through `JPype`. No script carries a `#@runtime` tag, so Ghidra picks whichever the install has.

The test suites take `GHIDRA_DIR` and `GHIDRA_RUNTIME` so both can be exercised:

```sh
tests/run_api_tests.sh                                            # auto-detect
GHIDRA_RUNTIME=pyghidra tests/run_api_tests.sh
GHIDRA_DIR=/opt/ghidra_11.4.2_PUBLIC GHIDRA_RUNTIME=jython tests/run_api_tests.sh
```

`analyzeHeadless` cannot start PyGhidra itself, so `tests/ghidra_headless.sh` goes through `pyghidra.ghidra_launch` for that runtime and calls `analyzeHeadless` directly for Jython.

## A few notes about weirdness in scripts
I try to write just about everything in `python` for these because it is quicker for me to write, but the two runtimes differ in enough places that a few oddities are needed that would not be if I wrote these in `java`.

### The wierd import line, and where it stopped working
Scripts still start with this, despite it being horrible practice for python:
```python
from __main__ import *
```

It is a hack to make script development easier: it pulls in the things `ghidra.program.flatapi.FlatProgramAPI` hands a script, like `currentProgram`, so a script can use them without ceremony.

Under Jython the running script *is* the `__main__` module, so this works from a script and from anything the script imports. **Under PyGhidra only the first half holds.** PyGhidra execs a script with a globals mapping that proxies a live `GhidraScript`, so bare names still resolve inside the script itself, but that mapping is never registered as `sys.modules['__main__']` -- `__main__` is the launcher. An imported module sees none of it, and every bare `currentProgram` or `getFunctionContaining` is a `NameError`.

So the rule is: **scripts may use the flat API directly, modules may not.** Everything under `ghidra_api/` goes through `_compat` instead:

```python
from ._compat import get_function_containing, resolve_program

def something(addr, program=None):
    program = resolve_program(program)
    func = get_function_containing(program, addr)
```

`_compat.flat_api()` is what makes that work on both: under Jython it reads `__main__`, and under PyGhidra it walks out to the script's own frame, whose globals carry `__this__` -- the `GhidraScript` -- and reads the API off that. `set_script_context()` pins it explicitly for an embedded interpreter or a harness where neither route applies.

### Other places the two runtimes disagree
`_compat` also covers these, and the test suite checks each on both:

* **Implementing a java interface.** Jython does it by subclassing; JPype refuses ("Java classes cannot be extended in Python") and wants `@JImplements` with `@JOverride` on each method. `implements()`, `java_interface_base()` and `override()` spell one declaration that works either way.
* **Java object identity.** Jython hands back one stable proxy per java object, so `is` answers "same object". JPype may build a fresh proxy per call, so `is` can be false for a single java object -- which silently turns an identity guard into "always different". `same_java_object()` compares through java's `equals()` instead. This one is worth watching for: it fails quietly rather than raising.
* **Reflection handles.** Jython hangs the `java.lang.Class` methods off the type object; JPype keeps them behind `class_`. `java_class_of()` accepts either.
* **Byte arrays.** `jarray` under Jython, `jpype.JArray` under PyGhidra, and java bytes are signed in both. `to_java_byte_array()`, `from_java_byte_array()` and `new_java_byte_array()` handle the conversion.
* **Catching java exceptions.** A java exception is not a python `Exception` under Jython, so a bare `except Exception` catches nothing. `CAUGHT_ERRORS` is the tuple to catch.

### Using Java's Reflection API
Inheriting from `java` classes in python works, but it doesn't work for everything. As I understand it, inheriting from a class in `java` would allow you to access `protected` methods, constructors, and fields. Inheriting from a `java` class in `Jython` does not immediately give you access to `protected` fields, which makes `Overriding` `protected` methods inacessible, despite it being relatively acceptable behavior for a `java` class. To work around this (and to avoid having to write code in `java`), I have utilized java's reflection API to enable this behavior. I try to limit it, but I also don't intend to rewrite java classes from ghidra in python to adjust their behavior if I don't have to.

