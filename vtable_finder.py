# Automatically search for vtables in a less than sane way
#@author Clifton Wolfe
#@category C++


import ghidra
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
from ghidra.app.decompiler import ClangFuncProto
from ghidra.app.decompiler import ClangVariableDecl
from ghidra.app.decompiler import DecompilerLocation
from ghidra.app.decompiler.component import DecompilerUtils
from collections import namedtuple, defaultdict
import java
import string
import re
import struct

from __main__ import *


def get_line_parent_for_clang_token(c_token):
    tok = c_token
    if hasattr(tok, 'getLineParent') and tok.getLineParent() is not None:
        return tok.getLineParent()
    while True:
        parent = tok.Parent()
        if parent is None:
            return None
        for sibling in parent:
            if hasattr(sibling, 'getLineParent') and sibling.getLineParent() is not None:
                return sibling.getLineParent()
        tok = parent
    return None


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
        self.currentProgram = currentProgram
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
        self._constructor_destructor_associated_functions = []


    def generate_address_range_rexp(self, minimum_addr, maximum_addr):
        address_pattern = self.generate_address_range_pattern(minimum_addr, maximum_addr)
        address_rexp = re.compile(address_pattern, re.DOTALL | re.MULTILINE)
        return address_rexp

    def generate_address_range_pattern(self, minimum_addr, maximum_addr):
        """
        Generate a regular expression pattern that can be used to match the bytes for an address between
        minimum_addr and maximum_addr (inclusive). This works best for small ranges, and will break somewhat if there are non-contiguous
        memory blocks
        """
        diff = maximum_addr - minimum_addr
        val = diff
        # calculate the changed number of bytes between the minimum_addr and the maximum_addr
        byte_count = 0
        while val > 0:
            val = val >> 8
            byte_count += 1

        # generate a sufficient wildcard character classes for all of the bytes that could fully change
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
            single_address_pattern = b''.join([packed_addr[:byte_count], boundary_byte_pattern, wildcard_pattern*wildcard_bytes])

        address_pattern = b"(%s)+" % single_address_pattern
        return address_pattern

    def get_memory_bounds(self, excluded_memory_block_names=["tdb"]):
        """
        Try to identify the bounds of memory that is currently mapped in. Some standard memory blocks (like `tdb` for microsoft binaries)
        are mapped in at ridiculous addresses (like 0xff00000000000000). If a memory block is mapped into this program
        """
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
        """
        Finds one or more pointers in a row using a regular expression. If no regular expression is provided, one will be generated
        based on the current memory blocks of the current program
        """
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
            iter_gen = re.finditer(address_rexp, search_bytes)
            match_count = 0
            # hacky loop over matches so that the recursion limit can be caught
            while True:
                try:
                    m = next(iter_gen)
                except StopIteration:
                    break
                except RuntimeError:
                    # this means that recursion went too deep
                    print("match hit recursion limit on match %d" % match_count)
                    break
                match_count += 1
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
        """
        Find runs of pointers and split them up based on references.
        NOTE: vtables that contain NULL pointers will likely break this as it currently works
        """
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
            # TODO: might need to rework this so that weirder vtables with
            # TODO: lots of null pointers in them are handled better

            # TODO: NULL pointers should probably be added to the list of
            # TODO: pointers, or found_vtable should have the `found_pointer`
            # TODO: appended to it so that calculation of vtable size is
            # TODO: correct for vtables that contain NULL pointers
            maybe_new_vtable_loc = found_pointer.location
            # only keep building a vtable if nothing is inbetween this
            # pointer and the previous one.
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

            # there were references to this address or there was no
            # established previous data, So start a new vtable
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
        """
        Walk back from `addr` until the last address that has references to it
        """
        while addr.compareTo(self.minimum_addr_addr) >= 0:
            try:
                addr = addr.subtract(self.ptr_size)
            except ghidra.program.model.address.AddressOutOfBoundsException:
                break
            if len(getReferencesTo(addr)) > 0:
                return addr
        return None


    def create_or_update_struct_from_found_vtable(self, found_vtable, newname="vtable", function_definition_datatype=False):
        """
        Using the FoundVTable `found_vtable`, either create a new struct if none exists at the address of the vtable or if it does
        exist update it to use the current names of the functions
        """
        location_sym = getSymbolAt(found_vtable.address)
        if location_sym is None:
            return None
        structure_name = "%s_%s" % (newname, str(found_vtable.address))
        # TODO: NULL fields in the middle of vtables cause this calculation to be too low
        vtable_byte_size = self.ptr_size*found_vtable.size
        symbols_to_delete = []
        vtable_data = getDataAt(found_vtable.address)
        # if there is already a defined structure at the vtable address, just get that structure and update it.
        if vtable_data is not None and vtable_data.isStructure():
            found_vtable.associated_struct = vtable_data.dataType
            self.update_associated_struct(found_vtable,function_definition_datatype)
            return
        start_addr_int = found_vtable.address.getOffset()
        # TODO: This initial method for creating field names is kind of a hack, and doesn't seem like reliable behavior for future ghidra releases
        # START of hacky field naming method
        # create symbols at each address to autofill struct field names
        for i, ptr in enumerate(found_vtable.pointers):
            points_to_sym = getSymbolAt(ptr)
            if points_to_sym is None:
                continue
            loc = self.addr_space.getAddress((i*self.ptr_size)+start_addr_int)
            # TODO: uncertain if this will create a pointer datatype at the address, but if it doesn't that needs to be done here
            createSymbol(loc, points_to_sym.name, False, False, SourceType.USER_DEFINED)
            symbols_to_delete.append((loc, points_to_sym.name))

        try:
            # this function uses the existing types of the data
            new_struct = self.struct_fact.createStructureDataType(self.currentProgram, found_vtable.address, vtable_byte_size, structure_name, True)
        except java.lang.IllegalArgumentException:
            return
        # delete the symbols that autofilled struct field names
        for loc, name in symbols_to_delete:
            removeSymbol(loc, name)

        # END of hacky field naming method
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

    def apply_vtables_to_program(self, function_definition_datatype=False, address_rexp=None):
        found_vtables = self.find_vtables(address_rexp=address_rexp)

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

    def decompile_function(self, func, timeout=60):
        self._ifc.openProgram(func.getProgram())
        res = self._ifc.decompileFunction(func, timeout, self._monitor)
        return res

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
        """
        Create mappings of which functions reference each vtable and which vtables are reference by each function.
        These reference mappings can be used later on to help identify inheritance associations between classes
        """
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
        """
        Using FoundVTables, identify functions that reference those vtables (and therefore) which functions can act as constructors
        or destructors for the classes which use those vtables. Then using the identified constructors and destructors, create new class
        structures if they do not already exist or auto fill them out if they do
        """
        self.find_vtable_references()
        print("\ndone getting references")
        # vtables that are only used by one or two functions are typically either abstract or impl vtables for that class or vtables
        # for embedded classes. tne one or two functions that reference them are typically either constructors or destructors. Identifying
        # and labeling these functions and automatically creating the class structures for them cleans up the vast majority of the
        # code related to

        # get a list of all of the vtable structure that have been found or created. These need to be checked against in case
        # the decompiler has associated one of these structs with a class' destructor/constructor, which indicates that a new class structure
        # will be needed, and that a `struct vtable**` was identified as the type by ghidra (because vtables are most commonly the first field)
        # in a class.
        all_vtable_structs = [i.associated_struct for i in self.found_vtables]
        print("\nIdentifying constructors and destructors")
        for found_vtable, functions in self.vtable_refs_from_funcs.items():
            # TODO: Maybe use pcode to identify which functions are constructor/destructor.
            # limiting this to vtables that only have a destructor and constructor for now
            # TODO: Since Identifying Constructors/Destructors based off of how many functions touch the vtable seems to work pretty well for
            # TODO: simple classes, so the same thing will likely work for some complex classes s
            if len(functions) != 2:
                continue

            # use the same struct across all of the functions for a specific vtable
            class_struct = None
            # if possible, functions should be sorted by whether or not they have a VoidDataType return type (aka destructors).
            # because, at least for windows binaries, destructors will assign vtables to the classes in reverse construction order,
            # so the actual vtable impl will be associated with the vtable field first, meaning that the datatype for the class' vtable
            # will correctly be associated with the field where it is assigned. This doesn't matter for classes without abstraction,
            # but for classes with abstraction (where the vtable filled with dummy function pointers is assigned first) this causes the field to
            # incorrectly be associated with the pure-virtual vtable
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

                do_param_assignment = True
                if class_struct is None:
                    state = getState()
                    # location = state.getCurrentLocation()
                    location = BytesFieldLocation(self.currentProgram, func.getEntryPoint())
                    tool = state.getTool()
                    # NOTE: this might only work with the gui
                    # NOTE: this class is accessible through the api, but is not documented in the api, so there is a risk of
                    # NOTE: it being deprecated at some point. For now it is a feature that is unlikely to be removed though
                    fos = FillOutStructureCmd(self.currentProgram, location, tool)
                    created_class_struct = fos.processStructure(param_high_var, func)
                    if not created_class_struct.isZeroLength():
                        print("created class struct for %s" % func.name)
                        class_struct = created_class_struct
                        self.created_class_structs.append(class_struct)
                    else:
                        continue
                else:
                    # TODO: for some constructors where a struct is both allocated and constructed in the same function,
                    # TODO: this methodology does not work correctly. For those cases, this should probably try to trace
                    # TODO: the pcode to identify the variable whose field is actually assigned the vtable pointer
                    c_token = self.get_clang_token_for_param(func, thisptr_ind)
                    if c_token is not None:
                        # print("skipping %s, couldn't find param token in func arguments" % func.name)
                        # TODO: validate that param type is correct here?
                        location = self.get_decompiler_location_for_tok(c_token)
                        tool = state.getTool()
                        fos = FillOutStructureCmd(self.currentProgram, location, tool)
                        # run a sort of `trial-run` to see if the variable is zero length.
                        # if the vtable had been written to a field, it would at least have the length
                        # of that pointer in the structure length
                        trial_created_class_struct = fos.processStructure(param_high_var, func)
                        if not trial_created_class_struct.isZeroLength():
                            fos.applyTo(self.currentProgram, self._monitor)
                        else:
                            do_param_assignment = False

                if do_param_assignment is True:
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
                self._constructor_destructor_associated_functions.append(func)

    def get_clang_token_for_param(self, func, param_ind=0):
        decomp_res = self.decompile_function(func)
        # something in decomp_res prevents tokens from populateing lineParent
        # This is to force the line parent to populate, looks like it is a lazy variable
        decomp_res.getDecompiledFunction().getC()
        found_token = None
        high_func = decomp_res.getHighFunction()
        proto = high_func.getFunctionPrototype()
        try:
            param = proto.getParam(param_ind)
        except:
            print("returning none for bad param ind")
            return None
        param_high_var = param.getHighVariable()
        ccode_markup = decomp_res.getCCodeMarkup()
        c_func_proto = None
        for tok in ccode_markup:
            if isinstance(tok, ClangFuncProto):
                c_func_proto = tok
                break

        if c_func_proto is None:
            return None
        for tok in c_func_proto:
            # additional validation might be needed, but this seems sufficient for now
            if not isinstance(tok, ClangVariableDecl):
                continue
            # just get the param name token, not the type
            name_tok = list(tok)[-1]
            tok_high_var = name_tok.getHighVariable()
            if tok_high_var.PCAddress == param_high_var.PCAddress and \
                tok_high_var.name == param_high_var.name:
                # HACK to work around lazy variable
                return name_tok
                found_token = name_tok
                break
        return None
        # commenting out this code for now, but since the ClangToken
        # code seems somewhat unreliable in some areas, keeping it
        # around in case everything breaks in a new release
        """
        if found_token is None:
            return None

        found_token_type = type(found_token)
        found_token_high_var = found_token.getHighVariable()
        # correct token has been found, but it has not been
        # associated with a line correctly
        for line in DecompilerUtils.toLines(ccode_markup):
            for tok in line.getAllTokens():
                if not found_token_type == type(tok):
                    continue
                tok_high_var = tok.getHighVariable()
                if tok_high_var.PCAddress == found_token_high_var.PCAddress and \
                    tok_high_var.name == found_token_high_var.name:
                    return tok

        return None
        """

    def get_decompiler_location_for_tok(self, c_token):
        high_var = c_token.getHighVariable()
        high_func = high_var.getHighFunction()
        func = high_func.getFunction()
        entrypoint = func.getEntryPoint()
        addr = high_var.getPCAddress()
        decomp_res = self.decompile_function(func)
        clang_line = get_line_parent_for_clang_token(c_token)
        # clang_line = c_token.getLineParent()
        line_num = clang_line.getLineNumber() - 1
        chr_off = 0
        # add up the string length of all of the tokens up until the token
        for t in clang_line.getAllTokens():
            if t == c_token:
                break
            chr_off += len(t.toString())
        # line_str = ''.join([i.toString() for i in clang_line.getAllTokens()])
        decomp_loc = DecompilerLocation(self.currentProgram, addr, entrypoint,
                                        decomp_res, c_token, line_num, chr_off)
        return decomp_loc


find_and_apply_vtables = True
identify_and_create_class_structures = True

if __name__ == "__main__" and not isRunningHeadless():
    find_and_apply_vtables = False
    identify_and_create_class_structures = False
    manually_set_memory_bounds = False
    choices = askChoices("Vtable Finder", "Select VTable analysis options",
                         ["find_and_apply_vtables",
                          "identify_and_create_class_structures",
                          "manually_set_memory_bounds"],
                         ["Find vtables and apply them to current program",
                          "Identify and create class structures",
                          "Manually set memory bounds for pointer search"])
    for choice in choices:
        if choice.find("find_and_apply_vtables") != -1:
            find_and_apply_vtables = True
        elif choice.find("identify_and_create_class_structures") != -1:
            identify_and_create_class_structures = True
        elif choice.find("manually_set_memory_bounds") != -1:
            manually_set_memory_bounds = True


vtf = VTableFinder(currentProgram)

address_rexp = None
if manually_set_memory_bounds is True:
    minimum_addr = askAddress("Minimum Address", "Minimum Address")
    maximum_addr = askAddress("Maximum Address", "Maximum Address")
    address_rexp = vtf.generate_address_range_rexp(minimum_addr.getOffset(), maximum_addr.getOffset())

if find_and_apply_vtables is True:
    print("\nfinding vtables")
    vtf.apply_vtables_to_program(address_rexp=address_rexp)


if identify_and_create_class_structures is True:
    print("\ncreating class structures")
    vtf.create_structs_for_classes()
    # and update all of the struct field names for vtables
    vtf.apply_vtables_to_program(address_rexp=address_rexp)


print("\nvtable finder done")
# func.signature.replaceArgument(thisptr_ind, "param_%d" % (thisptr_ind+1), UnsignedLongLongDataType(), "", SourceType.USER_DEFINED)
# vtf.dtm.addDataType(func.signature, DataTypeConflictHandler.REPLACE_HANDLER)
