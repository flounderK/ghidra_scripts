# Automatically search for vtables in a less than sane way
#@author Clifton Wolfe
#@category C++


from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.program.util import FunctionSignatureFieldLocation
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StructureDataType, PointerDataType, FunctionDefinitionDataType
from ghidra.program.model.data import StructureFactory
from ghidra.framework.plugintool import PluginTool
from ghidra.app.cmd.data import CreateStructureCmd
from ghidra.app.plugin.core.data import DataPlugin
from collections import namedtuple
import string
import re
import struct

from __main__ import *


FoundPointer = namedtuple("FoundPointer", ["points_to", "location"])

class FoundVTable:
    def __init__(self, address, pointers=None):
        self.address = address
        if pointers is not None:
            self.pointers = pointers
        else:
            self.pointers = []

    @property
    def size(self):
        return len(self.pointers)
    
    def __repr__(self):
        return "FoundVTable(address=%s, size=%d)" % (str(self.address), self.size)


class VTableFinder:
    def __init__(self, currentProgram):
        self.fm = currentProgram.getFunctionManager()
        self.dtm = currentProgram.getDataTypeManager()
        self.namespace_manager = currentProgram.getNamespaceManager()
        self.addr_fact = currentProgram.getAddressFactory()
        self.addr_space = self.addr_fact.getDefaultAddressSpace()
        self.mem = currentProgram.getMemory()
        self.little_endian = not self.mem.isBigEndian()
        self.sym_tab = currentProgram.getSymbolTable()
        self._stack_reg_offset = currentProgram.getRegister("sp").getOffset()

        self.ptr_size = self.addr_space.getPointerSize()
        if self.ptr_size == 4:
            self._get_ptr_size = self.mem.getInt
            self.is_64_bit = False
        elif self.ptr_size == 8:
            self._get_ptr_size = self.mem.getLong
            self.is_64_bit = True

        # pick the right packing symbols for this endianness and pointer size
        self.pack_sym = ""
        if self.little_endian is True:
            self.pack_endian = "<"
        else:
            self.pack_endian = ">"
        
        if self.is_64_bit is True:
            self.pack_code = "Q"
        else:
            self.pack_code = "I"
        
        self.pack_sym = self.pack_endian + self.pack_code

        self._null = self.addr_space.getAddress(0)
        self._global_ns = currentProgram.getGlobalNamespace()
        self._decomp_options = DecompileOptions()
        self._monitor = ConsoleTaskMonitor()
        self._ifc = DecompInterface()
        self._ifc.setOptions(self._decomp_options)
        self.refman = currentProgram.getReferenceManager()

    def generate_address_range_rexp(self, minimum_addr, maximum_addr):
        address_pattern = self.generate_address_range_pattern(minimum_addr, maximum_addr)
        address_rexp = re.compile(address_pattern, re.DOTALL | re.MULTILINE)
        return address_rexp
    
    def generate_address_range_pattern(self, minimum_addr, maximum_addr):
        diff = maximum_addr - minimum_addr
        val = diff
        byte_count = 0
        while val > 0:
            val = val >> 8
            byte_count += 1

        wildcard_bytes = byte_count - 1
        wildcard_pattern = b"[\x00-\xff]"
        boundary_byte_upper = (maximum_addr >> (wildcard_bytes*8)) & 0xff
        boundary_byte_lower = (minimum_addr >> (wildcard_bytes*8)) & 0xff
        # create a character class that will match the largest changing byte
        boundary_byte_pattern = b"[\\%s-\\%s]" % (bytearray([boundary_byte_lower]), bytearray([boundary_byte_upper]))

        address_pattern = b''
        single_address_pattern = b''
        if self.little_endian is True:
            packed_addr = struct.pack(self.pack_sym, minimum_addr)
            single_address_pattern = b''.join([wildcard_pattern*wildcard_bytes, boundary_byte_pattern, packed_addr[byte_count:]])
        else:
            packed_addr = struct.pack(self.pack_sym, minimum_addr)
            single_address_pattern =  b''.join([packed_addr[:byte_count], boundary_byte_pattern, wildcard_pattern*wildcard_bytes])
            
        address_pattern = b"(%s)+" % single_address_pattern
        return address_pattern

    def get_memory_bounds(self, excluded_memory_block_names=["tdb"]):
        minimum_addr = 0xffffffffffffffff
        maximum_addr = 0
        memory_blocks = list(getMemoryBlocks())
        for m_block in memory_blocks:
            # tdb is placed at a very large address that is well outside of the loaded range for most executables
            if m_block.name in excluded_memory_block_names:
                continue
            start = m_block.getStart().getOffset()
            end = m_block.getEnd().getOffset()
            if start < minimum_addr:
                minimum_addr = start
            if end > maximum_addr:
                maximum_addr = end
        return minimum_addr, maximum_addr
    

    def find_pointer_runs(self, address_rexp=None, additional_search_block_filter=None):
        if address_rexp is None:
            minimum_addr, maximum_addr = vtf.get_memory_bounds()
            address_rexp = vtf.generate_address_range_rexp(minimum_addr, maximum_addr)
        
        found_pointers = []
        memory_blocks = list(getMemoryBlocks()) 
        # filter out which memory blocks should actually be searched
        search_memory_blocks = [i for i in memory_blocks if i.getPermissions() == i.READ]
        if additional_search_block_filter is not None:
            search_memory_blocks = [i for i in search_memory_blocks if additional_search_block_filter(i) is True]
        # find and extract 
        for m_block in search_memory_blocks:
            if not m_block.isInitialized():
                continue
            region_start = m_block.getStart()
            region_start_int = region_start.getOffset()
            search_bytes = getBytes(region_start, m_block.getSize())
            for m in re.finditer(address_rexp, search_bytes):
                vtable_match_bytes = m.group()
                unpacked_addr_ints = struct.unpack_from(self.pack_endian + (len(vtable_match_bytes)//self.ptr_size)*self.pack_code, vtable_match_bytes)
                match_start = m.start()
                # calculate the actual address where each pointer was found at and save it off
                for i, addr_val in enumerate(unpacked_addr_ints):
                    location_int = region_start_int + match_start + (i*self.ptr_size)
                    location = self.addr_space.getAddress(location_int)
                    new_found_ptr = FoundPointer(self.addr_space.getAddress(addr_val), location)
                    found_pointers.append(new_found_ptr)
        return found_pointers

    def find_vtables(self, address_rexp=None, additional_search_block_filter=None):
        found_pointers = self.find_pointer_runs(address_rexp, additional_search_block_filter)
        found_pointers.sort(key=lambda a: a.location)
        memory_blocks = list(getMemoryBlocks()) 
        points_to_memory_blocks = [b for b in memory_blocks if b.name.startswith(".text")]
        # if no text section is found, fall back to a less efficient search that will search all of the initialized memory blocks
        if len(points_to_memory_blocks) == 0:
            points_to_memory_blocks = [i for i in memory_blocks if i.isInitialized()]
            has_text_section = False
        else:
            has_text_section = True
        found_vtables = set()
        current_vtable = []
        # dummy vtable
        last_found_vtable = FoundVTable(self._null)
        for found_pointer in found_pointers:
            any_valid_block_contains = False
            for m_block in points_to_memory_blocks:
                if not m_block.contains(found_pointer.points_to):
                    continue
                any_valid_block_contains = True
            # skip if it isn't pointing to something sane
            if any_valid_block_contains is False:
                continue
            
            location_sym = getSymbolAt(found_pointer.location)
            # ghidra's analysis should automatically label locations that are referenced, so
            # skip any that don't have references
            if location_sym is None:
                last_found_vtable.pointers.append(found_pointer.points_to)
                continue
            found_vtables.add(last_found_vtable)
            last_found_vtable = FoundVTable(found_pointer.location)
            last_found_vtable.pointers.append(found_pointer.points_to)
        
        if last_found_vtable is not None and last_found_vtable not in found_vtables:
            found_vtables.add(last_found_vtable)
            
        return list(found_vtables)


# def main():
vtf = VTableFinder(currentProgram)
found_vtables = vtf.find_vtables()
# pointer_runs = vtf.find_pointer_runs(additional_search_block_filter=lambda a: a.name == ".rdata")

# plugintool = PluginTool()
# plugin = DataPlugin()
# tool = plugin.getTool()
struct_fact = StructureFactory()
newname = "vtable"
for found_vtable in found_vtables:
    location_sym = getSymbolAt(found_vtable.address)
    if location_sym is None:
        continue
    current_name_str = location_sym.name
    if re.search("vb?f?table", current_name_str) is None:
        location_sym.setName(newname, SourceType.USER_DEFINED)

    structure_name = "blah_%s" % str(found_vtable.address)
    # new_struct = StructureDataType("vtable_%s" % str(found_vtable.address), found_vtable.size*vtf.ptr_size, vtf.dtm)
    # this function uses the existing types of the data
    new_struct = struct_fact.createStructureDataType(currentProgram, found_vtable.address, vtf.ptr_size*found_vtable.size, structure_name, True)
    # cmd = CreateStructureCmd(new_struct, found_vtable.address)
    # tool.execute(cmd, currentProgram)
    for i in range(found_vtable.size*vtf.ptr_size, vtf.ptr_size):
        datatype = PointerDataType()
        new_struct.replace(i, datatype, vtf.ptr_size)
        # new_struct.add(datatype, vtf.ptr_size)

    vtf.dtm.addDataType(new_struct, None)