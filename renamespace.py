# Change namespace of selected regions
#@author Clifton Wolfe
#@category C++
import ghidra
from ghidra.program.model.symbol import SourceType
import string
import re
import struct
# makes it easier for dev and testing
from __main__ import *


class PointerUtils:
    def __init__(self):
        self.addr_fact = currentProgram.getAddressFactory()
        self.addr_space = self.addr_fact.getDefaultAddressSpace()
        self.ptr_size = self.addr_space.getPointerSize()
        self.mem = currentProgram.getMemory()
        self.ptr_pack_sym = ""
        if self.ptr_size == 4:
            self.ptr_pack_sym = "I"
        elif self.ptr_size == 8:
            self.ptr_pack_sym = "Q"

        self.pack_endian = ""
        if self.mem.isBigEndian():
            self.pack_endian = ">"
        else:
            self.pack_endian = "<"

    def ptr_ints_from_bytearray(self, bytarr):
        bytarr = bytearray(bytarr)
        # truncate in case the bytarray isn't aligned to ptr size
        fit_len = len(bytarr) // self.ptr_size
        pack_code = "%s%d%s" % (self.pack_endian, fit_len, self.ptr_pack_sym)
        return struct.unpack_from(pack_code, bytarr)


def get_or_create_namespace(name, parent=None):
    if parent is None:
        parent = currentProgram.getGlobalNamespace()
    sym_tab = currentProgram.getSymbolTable()
    maybe_ns = sym_tab.getNamespace(name, parent)
    if maybe_ns:
        return maybe_ns
    maybe_ns = sym_tab.createNameSpace(parent, name,
                                       SourceType.USER_DEFINED)
    return maybe_ns


namespace_name = askString("Enter namespace", "Enter namespace")
namespace = get_or_create_namespace(namespace_name)
ptr_utils = PointerUtils()

all_selected_ptrs = []
for addr_range in currentSelection:
    start_addr = addr_range.minAddress
    size = addr_range.maxAddress.subtract(start_addr)+1
    selected_bytes = bytearray(getBytes(start_addr, size))
    selected_ptrs = [toAddr(i) for i in ptr_utils.ptr_ints_from_bytearray(selected_bytes)]
    all_selected_ptrs.extend(selected_ptrs)

for ptr in all_selected_ptrs:
    func = getFunctionAt(ptr)
    # skip functions that aren't known for now
    if func is None:
        continue
    if func.getParentNamespace() != namespace:
        func.setParentNamespace(namespace)


