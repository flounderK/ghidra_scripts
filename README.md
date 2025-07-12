# Ghidra Scripts


## API
Ghidra's API is still pretty minimal, so a lot of these scripts just add another layer of API on-top of ghidra's existing `FlatProgramAPI` for functions that I have found to be useful but that aren't easily accessible or that require a bit more setup than I feel that they should. In general, I will try to keep a naming scheme of `*_utils` to mirror the strategy present in a lot of ghidra's code of making `static` `*Utilities` classes, which are generally the most usable and useful parts of ghidra's existing API.

### call_ref_utils.py
Utilities for working will call references, mostly for following the call graph, finding callsites through thunks, finding all callsites for a function name, or creating new indirect call references

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

## A few notes about weirdness in scripts
I try to write just about everything in `python` for these because it is quicker for me to write, but because ghidra uses `Jython` certain oddities are needed to improve the usability or functionality for things that would not necessarily be needed if I wrote these in `java`.

### The wierd import line
I use the following line in almost all of the scripts, despite it being horrible practice for python:
```python
from __main__ import *
```

This is a hack to make script development easier, as it allows you to do something like `from call_ref_utils import *` from the ghidra python interpreter and have the import work correctly, even if you utilize things that are default imports from `ghidra.program.flatapi.FlatProgramAPI`, like the `currentProgram` variable. I might change this in the future to make the scripts less cursed.

### Using Java's Reflection API
Inheriting from `java` classes in python works, but it doesn't work for everything. As I understand it, inheriting from a class in `java` would allow you to access `protected` methods, constructors, and fields. Inheriting from a `java` class in `Jython` does not immediately give you access to `protected` fields, which makes `Overriding` `protected` methods inacessible, despite it being relatively acceptable behavior for a `java` class. To work around this (and to avoid having to write code in `java`), I have utilized java's reflection API to enable this behavior. I try to limit it, but I also don't intend to rewrite java classes from ghidra in python to adjust their behavior if I don't have to.

