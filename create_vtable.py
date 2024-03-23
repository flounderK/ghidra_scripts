# Create and update vtables (vftables) 
# @author Clifton Wolfe
# @category C++
# @keybinding ctrl 5
# @menupath Tools.Automation.Create Vtable
# @toolbar 

from __main__ import *
from ghidra.program.model.address import AddressSet
from ghidra.program.model.address import AddressRangeImpl
from ghidra.program.model.symbol import DataRefType
from ghidra.program.database.symbol import FunctionSymbol
from ghidra.program.database.symbol import CodeSymbol
from ghidra.program.database.code import DataDB
from ghidra.program.database.code import InstructionDB
from ghidra.program.model.data import StructureDataType
from datatype_utils import getVoidPointerDatatype
import struct
import logging 

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


def containsInstructions(address, program=None):
    """
    Check if the address contains instructions. 
    """
    if program is None:
        program = currentProgram
    cu = program.getListing().getCodeUnitAt(address)
    return isinstance(cu, InstructionDB)


def addressContainsUnownedAssembly(address, program=None):
    """
    Check if the address contains valid instructions but is not
    within a function
    """
    if program is None:
        program = currentProgram
    cu = program.getListing().getCodeUnitAt(address)
    if not isinstance(cu, InstructionDB):
        return False
    maybe_func = getFunctionContaining(address)
    return maybe_func is None


def guessVtableByteSize(address, program=None, allow_null_ptrs=True):
    """
    Make an educated guess at the valid size of a vtable 
    """
    if program is None:
        program = currentProgram
    refman = program.getReferenceManager()
    ptr_size = program.getDefaultPointerSize()
    mem = program.getMemory()
    ptr_pack_end = ">" if mem.isBigEndian() else "<"
    ptr_pack_sym = "I" if ptr_size == 4 else "Q"
    ptr_pack_code = ptr_pack_end + ptr_pack_sym 
    listing = program.getListing()
    # skip the first entry because there are references to it
    curr_addr = address.add(ptr_size)
    last_valid_vtable_entry = address
    to_refs = []
    addr_sym = None
    while len(to_refs) == 0 and addr_sym is None:
        to_refs = list(refman.getReferencesTo(curr_addr))       
        maybe_ptr_bytes = bytearray(getBytes(curr_addr, ptr_size))
        maybe_func_addr_int = struct.unpack(ptr_pack_code, maybe_ptr_bytes)[0]
        maybe_func_addr = toAddr(maybe_func_addr_int)
        addr_sym = getSymbolAt(curr_addr)
        # check to see if it is actually valid code instead of a pointer to other data
        # Can't use refs for this because sometimes an address isn't identified as an address
        # and doesn't generate the reference
        is_valid_addr = mem.getRangeContaining(maybe_func_addr) is not None
        if is_valid_addr is True:
            # TODO: the structure of this loop should be untangled. for now just repeat loop exit critera
            if len(to_refs) == 0 and addr_sym is None:
                cu = listing.getCodeUnitAt(maybe_func_addr)
                if isinstance(cu, InstructionDB):
                    # this means that it is a label or a func
                    # save the last valid reference to a function or label as the end of the vtable
                    last_valid_vtable_entry = curr_addr 
        elif maybe_func_addr_int == 0 and allow_null_ptrs is True:
            # in some binaries it is entirely valid to have NULL pointers for vtable functions. 
            last_valid_vtable_entry = curr_addr
        curr_addr = curr_addr.add(ptr_size)
    # add ptr size so that the bounds of the vtable include the last valid pointer
    vtable_guessed_end = last_valid_vtable_entry.add(ptr_size)
    vtable_size_guess = vtable_guessed_end.subtract(address)
    return vtable_size_guess


def extractAddressTableEntries(address, table_size, program=None):
    """
    Extracts the bytes from the specified address as an array of addresses
    """
    if program is None:
            program = currentProgram
    ptr_size = program.getDefaultPointerSize()
    mem = program.getMemory()
    ptr_pack_end = ">" if mem.isBigEndian() else "<"
    ptr_pack_sym = "I" if ptr_size == 4 else "Q"
    vtable_bytes = bytearray(getBytes(address, table_size))
    num_ptrs = (table_size // ptr_size)
    pack_code = "%s%d%s" % (ptr_pack_end, num_ptrs, ptr_pack_sym)
    table_addrs = [toAddr(i) for i in struct.unpack_from(pack_code, vtable_bytes)]
    return table_addrs


def createFunctionsForVtableLabels(address, vtable_size, program=None):
    """
    Iterate through the embedded addresses at the specified address and create functions for the addresses
    that are valid and contains instructions, but are not already functions
    """
    if program is None:
        program = currentProgram
    mem = program.getMemory()
    vtable_addrs = extractAddressTableEntries(address, vtable_size, program=program)
    for addr in vtable_addrs:
        is_valid_address = mem.getRangeContaining(addr) is not None
        if is_valid_address is False:
            continue
        if addressContainsUnownedAssembly(addr, program=program) is True:
            createFunction(addr, None)


def createStringForNamespace(curr_ns):
    ns_strs = []
    while curr_ns:
        ns_strs.append(curr_ns.getName())
        curr_ns = curr_ns.getParentNamespace()
    return "_".join(ns_strs[::-1])



def createNewVtableAtAddress(address, vtable_size=None, referring_func=None, program=None):
    """
    Create a new vtable datatype based on the data at the specified address
    """
    if program is None:
        program = currentProgram
    if referring_func is not None:
        namespace = referring_func.getParentNamespace()
    else:
        namespace = program.getGlobalNamespace()
    
    vtable_prefix = ""
    global_namespace = program.getGlobalNamespace() 
    if namespace != global_namespace:
        # if the namespace for the function is not the global namespace, try to make an 
        # appropriate name for the new vtable
        vtable_prefix = createStringForNamespace(namespace) + "_"

    if vtable_size is None:
        vtable_size = guessVtableByteSize(address, program=program)
    # Fix up the Label pointers and make them into functions
    createFunctionsForVtableLabels(address, vtable_size, program=program)
    # now create the actual struct
    dtm = program.getDataTypeManager()
    new_struct = StructureDataType("%svftable_%s" % (vtable_prefix, str(address)), vtable_size)
    ptr_size = program.getDefaultPointerSize()
    voidp_dt = getVoidPointerDatatype()
    table_addrs = extractAddressTableEntries(address, vtable_size, program=program)
    # update the new datatype by setting the field name to something recognizable 
    # as a function pointer and setting the type to void*
    for ind, addr in enumerate(table_addrs):
        offset = ind*ptr_size
        func = getFunctionAt(addr)
        field_name = None
        if func is not None:
            field_name = "%s_%#x" % (func.name, offset)
        new_struct.replaceAtOffset(offset, voidp_dt, ptr_size, field_name, None)
    dtm.addDataType(new_struct, None)
    return new_struct


def createOrUpdateVtableAtAddress(address, vtable_size=None, referring_func=None, program=None):
    if program is None:
        program = currentProgram
    # TODO: add update
    vtable_dt = createNewVtableAtAddress(address, vtable_size=vtable_size, referring_func=referring_func, program=program)
    return vtable_dt

def create_vtable_entrypoint():
    selection = state.getCurrentSelection()
    currLoc = state.getCurrentLocation()
    addr_set = AddressSet()
    vtable_address = None
    referring_func = None
    vtable_size = None
    if selection is not None:
        pass
    elif currLoc is not None:
        if hasattr(currLoc, "getToken"):
            tok = currLoc.getToken()
            referring_func = getFunctionAt(currLoc.getFunctionEntryPoint())
            # unless there is a better way to find where a token is referring to, 
            # have to iterate over the addresses of the token to find where it is pointing
            refman = currentProgram.getReferenceManager()
            addr_range = AddressRangeImpl(tok.minAddress, tok.maxAddress)
            to_addrs = []
            for addr in addr_range.iterator():
                for ref in refman.getReferencesFrom(addr):
                    # because this is only looking for vtables, drop all non-data types of 
                    # references 
                    if not isinstance(ref.referenceType, DataRefType):
                        continue
                    to_addrs.append(ref.toAddress)
            # TODO: find a better way to filter these out, if there are in fact 
            # TODO: multiple references
            num_to_addrs = len(to_addrs)
            if num_to_addrs != 1:
                if num_to_addrs > 1:
                    log.critical("A critical assumption of the script has been broken. There are more than two references from the same token")
                elif num_to_addrs < 1:
                    log.error("No references from the token")
                return 
            vtable_address = to_addrs[0]
        else:
            vtable_address = currLoc.getAddress()
    
    createOrUpdateVtableAtAddress(vtable_address, vtable_size=vtable_size, referring_func=referring_func, program=currentProgram)
    

if __name__ == "__main__":
    create_vtable_entrypoint()