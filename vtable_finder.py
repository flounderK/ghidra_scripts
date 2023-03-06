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
from ghidra.app.plugin.core.decompile.actions import FillOutStructureCmd
from ghidra.program.util import FunctionSignatureFieldLocation
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StructureDataType, PointerDataType, FunctionDefinitionDataType, UnsignedLongLongDataType
from ghidra.program.model.data import StructureFactory
from ghidra.program.database.data import StructureDB
from ghidra.program.model.data import VoidDataType
from ghidra.framework.plugintool import PluginTool
from ghidra.app.cmd.data import CreateStructureCmd
from ghidra.app.plugin.core.data import DataPlugin
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.util.exception import DuplicateNameException
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.util import BytesFieldLocation
from collections import namedtuple, defaultdict
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
        self.associated_struct = None

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
        self.struct_fact = StructureFactory()
        self.listing = currentProgram.getListing()

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
        self.found_vtables = []
        self.minimum_addr_int, self.maximum_addr_int = self.get_memory_bounds()
        self.minimum_addr_addr = toAddr(self.minimum_addr_int)
        self.maximum_addr_addr = toAddr(self.maximum_addr_int)
        self.function_to_vtable_refs = {}
        self.vtable_refs_from_funcs = {}
        self.created_class_structs = []
        

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
            minimum_addr, maximum_addr = self.get_memory_bounds()
            address_rexp = self.generate_address_range_rexp(minimum_addr, maximum_addr)
        
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
        last_location_addr = None
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
            
            location_refs = list(getReferencesTo(found_pointer.location))
            is_next_linear_pointer = True
            if last_location_addr is not None and not last_location_addr.add(self.ptr_size).equals(found_pointer.location):
                is_next_linear_pointer = False
            # TODO: might need to rework this so that weirder vtables with lots of null pointers in them are
            # TODO: handled better
            maybe_new_vtable_loc = found_pointer.location
            # only keep building a vtable if nothing is inbetween this pointer and the previous one.
            if len(location_refs) == 0 and is_next_linear_pointer is True:
                last_location_addr = found_pointer.location
                last_found_vtable.pointers.append(found_pointer.points_to)
                continue
            elif len(location_refs) == 0 and is_next_linear_pointer is False:
                prev_referenced_addr = self.get_previous_referenced_address(found_pointer.location)
                if prev_referenced_addr is not None and prev_referenced_addr.equals(last_found_vtable.address):
                    last_location_addr = found_pointer.location
                    last_found_vtable.pointers.append(found_pointer.points_to)
                    continue
                elif prev_referenced_addr is not None:
                    # if it gets to this point, there is some data between this pointer and the start of the last vtable that 
                    # is independently referenced. since this location had no references, it should be considered a child of 
                    # the previously referenced data, not the last vtable (however far back that might be)
                    maybe_new_vtable_loc = prev_referenced_addr

            
            # there were references to this address or there was no established previous data, So start a new vtable
            found_vtables.add(last_found_vtable)
            last_found_vtable = FoundVTable(maybe_new_vtable_loc)
            last_location_addr = found_pointer.location
            last_found_vtable.pointers.append(found_pointer.points_to)
        
        if last_found_vtable is not None and last_found_vtable not in found_vtables:
            found_vtables.add(last_found_vtable)
        self.found_vtables = list(found_vtables)
        return list(found_vtables)


    def find_existing_refs(self, start_addr, end_addr):
        references = []
        addr_set = AddressSet(start_addr, end_addr)
        it = self.refman.getReferenceSourceIterator(addr_set, True)
        while it.hasNext():
            addr = it.next()
            refs = self.refman.getReferencesFrom(addr)
            for r in refs:
                references.append(r)
        return references
    
    def get_previous_referenced_address(self, addr, max_look_back=64):
        while addr.compareTo(self.minimum_addr_addr) >= 0:
            addr = addr.subtract(self.ptr_size)
            if len(getReferencesTo(addr)) > 0:
                return addr
        return None


    def create_or_update_struct_from_found_vtable(self, found_vtable, newname="vtable", function_definition_datatype=False):
        location_sym = getSymbolAt(found_vtable.address)
        if location_sym is None:
            return None
        structure_name = "%s_%s" % (newname, str(found_vtable.address))
        vtable_byte_size = self.ptr_size*found_vtable.size
        symbols_to_delete = []
        vtable_data = getDataAt(found_vtable.address)
        if vtable_data is not None and vtable_data.isStructure():
            found_vtable.associated_struct = vtable_data.dataType
            self.update_associated_struct(found_vtable,function_definition_datatype)
            # update structure fields here
            return
        start_addr_int = found_vtable.address.getOffset()
        # create symbols at each address to autofill struct field names
        for i, ptr in enumerate(found_vtable.pointers):
            points_to_sym = getSymbolAt(ptr)
            if points_to_sym is None:
                continue
            loc = self.addr_space.getAddress((i*self.ptr_size)+start_addr_int)
            createSymbol(loc, points_to_sym.name, False, False, SourceType.USER_DEFINED)
            symbols_to_delete.append((loc, points_to_sym.name))

        # new_struct = StructureDataType("vtable_%s" % str(found_vtable.address), found_vtable.size*self.ptr_size, self.dtm)
        # this function uses the existing types of the data
        new_struct = self.struct_fact.createStructureDataType(currentProgram, found_vtable.address, vtable_byte_size, structure_name, True)
        # delete the symbols that autofilled struct field names
        for loc, name in symbols_to_delete:
            removeSymbol(loc, name)
        # cmd = CreateStructureCmd(new_struct, found_vtable.address)
        start_addr = found_vtable.address
        end_addr = self.addr_space.getAddress(start_addr.getOffset() + (vtable_byte_size-1))
        # saved_refs = self.find_existing_refs(start_addr, end_addr)
        # area has to be clear to apply
        self.listing.clearCodeUnits(start_addr, end_addr, False)
        self.listing.createData(start_addr, new_struct, vtable_byte_size)

        current_name_str = location_sym.name
        if re.search("vb?f?table", current_name_str, re.IGNORECASE) is None:
            location_sym.setName(newname, SourceType.USER_DEFINED)
        """
        for i in range(found_vtable.size):
            datatype = PointerDataType()
            try:
                new_struct.replace(i*self.ptr_size, datatype, self.ptr_size)
            except:
                pass
            # new_struct.add(datatype, self.ptr_size)
        """
        self.dtm.addDataType(new_struct, None)
        found_vtable.associated_struct = new_struct
        self.update_associated_struct(found_vtable, function_definition_datatype)

    def apply_vtables_to_program(self, function_definition_datatype=False):
        found_vtables = self.find_vtables()

        for found_vtable in found_vtables:
            location_sym = getSymbolAt(found_vtable.address)
            if location_sym is None:
                continue
            
            self.create_or_update_struct_from_found_vtable(found_vtable, function_definition_datatype=function_definition_datatype)
    
    def update_associated_struct(self, found_vtable, function_defininition_datatype=False):
        # get associated struct if it hasn't been assigned yet
        if found_vtable.associated_struct is None:
            vtable_data = getDataAt(found_vtable.address)
            if not vtable_data.isStructure():
                return
            found_vtable.associated_struct = vtable_data.dataType
        
        field_name_counts = defaultdict(lambda: 0)
        associated_struct = found_vtable.associated_struct
        for ptr, component in zip(found_vtable.pointers, associated_struct.getComponents()):
            points_to_sym = getSymbolAt(ptr)
            if points_to_sym is None:
                continue
            current_field_name = component.getFieldName()
            current_sym_name = points_to_sym.getName()
            func = self.listing.getFunctionAt(ptr)
            if func is not None and function_defininition_datatype is True:
                sig = func.getSignature()
                func_def = FunctionDefinitionDataType(sig)
                component.setDataType(func_def)
            else:
                component.setDataType(PointerDataType())
            if current_sym_name == current_field_name:
                continue
            
            try:
                component.setFieldName(current_sym_name)
            except DuplicateNameException:
                count = field_name_counts[current_sym_name]
                component.setFieldName("%s_%d" % (current_sym_name, count))
            field_name_counts[current_sym_name] += 1

        # replace the old type with the new modified type
        self.dtm.addDataType(associated_struct, DataTypeConflictHandler.REPLACE_HANDLER)

    def get_high_function(self, func, timeout=60):
        """
        Get a HighFunction for a given function
        """
        self._ifc.openProgram(func.getProgram())
        res = self._ifc.decompileFunction(func, timeout, self._monitor)
        high_func = res.getHighFunction()
        return high_func

    def get_datatype_of_thisptr(self, func, thisptr_param_index=0):
        """
        Get the datatype of a Function's `this` pointer.
        """
        # if func.getCallingConvention().name != self._thiscall_str:
        #     return None
        high_func = self.get_high_function(func)
        prot = high_func.getFunctionPrototype()
        num_params = prot.getNumParams()
        if num_params == 0:
            return None
        maybe_this = prot.getParam(thisptr_param_index)
        return maybe_this.getDataType()
    
    def get_return_datatype(self, func):
        """
        Get the datatype of a Function's return value
        """
        high_func = self.get_high_function(func)
        prot = high_func.getFunctionPrototype()
        return prot.getReturnType()

    def find_vtable_references(self):
        function_to_vtable_refs = defaultdict(set)
        vtable_refs_from_funcs = defaultdict(set)
        
        # make some mappings that will be helpful for tracing associations between vtables and functions
        for found_vtable in self.found_vtables:
            refs = list(getReferencesTo(found_vtable.address))
            referring_functions = list(set([self.listing.getFunctionContaining(r.fromAddress) for r in refs]))
            for func in referring_functions:
                if func is None:
                    continue
                function_to_vtable_refs[func].add(found_vtable)
                vtable_refs_from_funcs[found_vtable].add(func)

        # put things back into lists for easier indexing
        self.function_to_vtable_refs = {k: list(v) for k, v in function_to_vtable_refs.items()}
        self.vtable_refs_from_funcs = {k: list(v) for k, v in vtable_refs_from_funcs.items()}

    def create_structs_for_classes(self, thisptr_ind=0, rename_funcs=True):
        self.find_vtable_references()
        print("\ndone getting references")
        # vtables that are only used by one or two functions are typically either abstract or impl vtables for that class or vtables
        # for embedded classes. tne one or two functions that reference them are typically either constructors or destructors. Identifying
        # and labeling these functions and automatically creating the class structures for them cleans up the vast majority of the 
        # code related to 
        all_vtable_structs = [i.associated_struct for i in self.found_vtables]
        print("\nIdentifying constructors and destructors")
        for found_vtable, functions in self.vtable_refs_from_funcs.items():
            # limiting this to vtables that only have a destructor and constructor for now
            # TODO: maybe use pcode to identify which functions are constructor/destructor
            if len(functions) != 2:
                continue
            
            # use the same struct across all of the functions for a specific vtable
            class_struct = None
            # if possible, functions should be sorted by whether or not they have a VoidDataType return type (aka destructors).
            # because, at least for windows binaries, destructors will assign vtables to the classes in reverse construction order,
            # so the actual vtable impl will be associated with the vtable field first, meaning that the datatype for the class' vtable 
            # will correctly be associated with the field where it is assigned. This doesn't matter for classes without abstraction, 
            # but for classes with abstraction (where the vtable filled with dummy function pointers is assigned first) this causes the field to
            # incorrectly be associated with the pure-virtual vtable. As an added bonus, using the 

            functions.sort(key=lambda func: isinstance(self.get_return_datatype(func), VoidDataType), reverse=True)

            for func in functions:
                high_func = self.get_high_function(func)
                prot = high_func.getFunctionPrototype()

                param = prot.getParam(thisptr_ind)
                if param is None:
                    continue
                is_constructor = True
                if isinstance(prot.getReturnType(), VoidDataType):
                    is_constructor = False
                orig_dt = self.get_datatype_of_thisptr(func, thisptr_ind)
                dt = orig_dt
                # get real pointed to datatype
                while isinstance(dt, PointerDataType):
                    dt = dt.dataType

                if dt not in all_vtable_structs and isinstance(dt, StructureDB):
                    class_struct = dt
                    self.created_class_structs.append(class_struct)
                    continue

                # reset param type to `pointer` so that everything in the struct won't be interpreted as a vtable* as an artifact
                # of the pervious param's type `vtable**`
                HighFunctionDBUtil.updateDBVariable(param, param.name, PointerDataType(), SourceType.USER_DEFINED)
                # refetch the param because the type has changed
                high_func = self.get_high_function(func)
                prot = high_func.getFunctionPrototype()
                param = prot.getParam(thisptr_ind)
                param_high_var = param.getHighVariable()
                
                # TODO: the fill out command should probably be run for additional functions too to 
                # TODO: fill in more fields of the class. Unfortunately, the function `processStructure` only creates new structures, it
                # TODO: does not add on to existing ones. that command will require an actual decompilerLocation, which is used to specify 
                # TODO: which variable to fill out
                if class_struct is None:
                    state = getState()
                    # location = state.getCurrentLocation()
                    location = BytesFieldLocation(currentProgram, func.getEntryPoint())
                    tool = state.getTool()
                    # NOTE: this might only work with the gui
                    # NOTE: this class is accessible through the api, but is not documented in the api, so there is a risk of
                    # NOTE: it being deprecated at some point. For now it is a feature that is unlikely to be removed though
                    fos = FillOutStructureCmd(currentProgram, location, tool)
                    created_class_struct = fos.processStructure(param_high_var, func)
                    if not created_class_struct.isZeroLength():
                        print("created class struct for %s" % func.name)
                        class_struct = created_class_struct
                        self.created_class_structs.append(class_struct)
                    else:
                        continue

                try:
                    HighFunctionDBUtil.updateDBVariable(param, param.name, PointerDataType(class_struct), SourceType.USER_DEFINED)
                except:
                    print("failed to assign struct pointer for %s" % func.name)
                if is_constructor is True:
                    if func.name.startswith('FUN_') and rename_funcs is True:
                        func.setName("%s_constructor" % class_struct.name, SourceType.USER_DEFINED)
                    # get an updated version of the high function again
                    high_func = self.get_high_function(func)
                    HighFunctionDBUtil.commitReturnToDatabase(high_func, SourceType.USER_DEFINED)
                    # ret_type = prot.getReturnType()
                    # ret_type_high_var = ret_type.getHighVariable()
                    # HighFunctionDBUtil.updateDBVariable(ret_type_high_var, ret_type_high_var.name, new_struct, SourceType.USER_DEFINED)
                else:
                    if func.name.startswith('FUN_') and rename_funcs is True:
                        func.setName("%s_destructor" % class_struct.name, SourceType.USER_DEFINED)


find_and_apply_vtables = True
identify_and_create_class_structures = True

if __name__ == "__main__" and not isRunningHeadless():
    find_and_apply_vtables = False
    identify_and_create_class_structures = False
    choices = askChoices("Vtable Finder", "Select VTable analysis options", 
                        ["find_and_apply_vtables", "identify_and_create_class_structures"], 
                        ["Find vtables and apply them to current program", 
                         "Identify and create class structures"])
    for choice in choices:
        if choice.find("find_and_apply_vtables") != -1:
            find_and_apply_vtables = True
        elif choice.find("identify_and_create_class_structures") != -1:
            identify_and_create_class_structures = True
        

vtf = VTableFinder(currentProgram)

if find_and_apply_vtables is True:
    print("\nfinding vtables")
    vtf.apply_vtables_to_program()


if identify_and_create_class_structures is True:
    print("\ncreating class structures")
    vtf.create_structs_for_classes()
    # and update all of the struct field names for vtables
    vtf.apply_vtables_to_program()


print("\nvtable finder done")
# func.signature.replaceArgument(thisptr_ind, "param_%d" % (thisptr_ind+1), UnsignedLongLongDataType(), "", SourceType.USER_DEFINED)
# vtf.dtm.addDataType(func.signature, DataTypeConflictHandler.REPLACE_HANDLER)
