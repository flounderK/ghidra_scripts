# Ghidra Scripts


## API
Ghidra's API is still pretty minimal, so a lot of these scripts just add another layer of API on-top of ghidra's existing `FlatProgramAPI` for functions that I have found to be useful but that aren't easily accessible or that require a bit more setup than I feel that they should. In general, I will try to keep a naming scheme of `*_utils` to mirror the strategy present in a lot of ghidra's code of making `static` `*Utilities` classes, which are generally the most usable and useful parts of ghidra's existing API.

### call_ref_utils.py
Utilities for working will call references, mostly for following the call graph, finding callsites through thunks, finding all callsites for a function name, or creating new indirect call references

### byte_search_utils.py
Wrapper around ghidra's built-in memory search service (`ghidra.features.base.memsearch`, what the Search -> Memory dialog drives). Supports exact byte sequences, per-byte masks, and java regular expressions over bytes, with the same alignment and code-unit filters the GUI offers. `find_any` searches for many patterns in as few passes over memory as possible, which matters because re-reading memory, not matching, is what makes a large scan slow.

Note that a pattern longer than 100 bytes is refused rather than silently unreliable: the searcher only lets a match run 100 bytes past the end of a search chunk, so a longer pattern gets missed whenever it straddles a chunk boundary. Search a prefix and confirm the rest with `read_memory`.

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

