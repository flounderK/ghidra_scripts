# Ghidra Scripts


## API
Ghidra's API is still pretty minimal, so a lot of these scripts just add another layer of API on-top of ghidra's existing `FlatProgramAPI` for functions that I have found to be useful but that aren't easily accessible or that require a bit more setup than I feel that they should. In general, I will try to keep a naming scheme of `*_utils` to mirror the strategy present in a lot of ghidra's code of making `static` `*Utilities` classes, which are generally the most usable and useful parts of ghidra's existing API.

### call_ref_utils.py
Utilities for working will call references, mostly for following the call graph or finding callsites through thunks.


### datatype_utils.py
Utilities for finding datatypes, finding datatypes that meet certain constraints, finding datatype usage within other datatypes, and finding field usage across the program as a whole.

### decomp_utils.py
Utilities for interacting with ghidra's decompiler and `PCODE` as well as making associations between disassembled instructions, pcode operations, and decompiled pseudo-c. Also includes some utilities related to forward/backward slicing.

### java_reflection_utils.py
Utilities for interacting with `java`'s reflection API through python

### loopfinder.py
Utilities for interacting with loops.

### pointer_utils.py
Utilities for searching for embedded addresses or address ranges

## addr_search.py
Search for an embedded address. If ghidra doesn't find a reference to a function and you think it is getting called, run this script on the address to find potential references to it.

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

