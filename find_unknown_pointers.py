from __main__ import *
from ghidra.program.model.address import AddressSet
import struct
import re
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


def applyDataTypeAtAddress(address, datatype, size=None, program=None):
    if program is None:
        program = currentProgram
    if size is None:
        size = datatype.getLength()
    listing = program.getListing()
    listing.clearCodeUnits(address, address.add(size), False)
    listing.createData(address, datatype, size)



def gen_address_range_rexp(minimum_addr, maximum_addr, program=None):
    if program is None:
        program = currentProgram

    ptr_size = program.getDefaultPointerSize()
    mem = program.getMemory()
    is_big_endian = mem.isBigEndian()
    ptr_pack_sym = ""
    if ptr_size == 4:
        ptr_pack_sym = "I"
    elif ptr_size == 8:
        ptr_pack_sym = "Q"

    pack_endian = ""
    if is_big_endian is True:
        pack_endian = ">"
    else:
        pack_endian = "<"
    ptr_pack_code = pack_endian + ptr_pack_sym

    diff = maximum_addr - minimum_addr
    val = diff
    # calculate the changed number of bytes between the minimum_addr and the maximum_addr
    byte_count = 0
    while val > 0:
        val = val >> 8
        byte_count += 1

    # generate a sufficient wildcard character classes for all of the bytes that could fully c
    wildcard_bytes = byte_count - 1
    wildcard_pattern = "[\\x00-\\xff]"
    boundary_byte_upper = (maximum_addr >> (wildcard_bytes*8)) & 0xff
    boundary_byte_lower = (minimum_addr >> (wildcard_bytes*8)) & 0xff
    if boundary_byte_upper < boundary_byte_lower:
        boundary_byte_upper, boundary_byte_lower = boundary_byte_lower, boundary_byte_upper
    # create a character class that will match the largest changing byte
    # lower_byte = bytearray([boundary_byte_lower])
    # upper_byte = bytearray([boundary_byte_upper])
    boundary_byte_pattern = "[\\x%02x-\\x%02x]" % (boundary_byte_lower, boundary_byte_upper)
    address_pattern = ''
    single_address_pattern = ''
    if is_big_endian is False:
        packed_addr = struct.pack(ptr_pack_code, minimum_addr)
        single_address_pattern = ''.join([wildcard_pattern*wildcard_bytes,
                                          boundary_byte_pattern])
        for i in packed_addr[byte_count:]:
            single_address_pattern += "\\x%02x" % ord(i)
    else:
        packed_addr = struct.pack(ptr_pack_code, minimum_addr)
        for i in packed_addr[:byte_count]:
            single_address_pattern += "\\x%02x" % ord(i)
        single_address_pattern = ''.join([boundary_byte_pattern,
                                          wildcard_pattern*wildcard_bytes])
    address_pattern = "(%s)" % single_address_pattern
    return address_pattern


def create_full_memory_rexp(program=None):
    if program is None:
        program = currentProgram
    patterns = []
    # get an address set for all current memory blocks
    for m_block in getMemoryBlocks():
        start = m_block.start.getOffsetAsBigInteger()
        end = m_block.end.getOffsetAsBigInteger()
        pat = gen_address_range_rexp(start, end)
        log.debug("adding pattern '%s'" % pat)
        patterns.append(pat)

    full_pat = '(%s)' % '|'.join(patterns)
    log.debug("full pattern '%s'" % full_pat)
    return full_pat


def create_full_mem_addr_set():
    existing_mem_addr_set = AddressSet()
    for m_block in getMemoryBlocks():
        existing_mem_addr_set.add(m_block.getAddressRange())
    return existing_mem_addr_set


def find_full_mem_pointers(program=None, align_to=4):
    if program is None:
        program = currentProgram
    existing_mem_addr_set = create_full_mem_addr_set()
    full_pat = create_full_memory_rexp(program=program)
    for addr in findBytes(existing_mem_addr_set, full_pat, 100000, align_to, True):
        yield addr


def identify_unknown_pointers(program=None, align_to=4):
    if program is None:
        program = currentProgram
    dtm = program.getDataTypeManager()
    ptr_dt = [i for i in dtm.getAllDataTypes() if i.name == 'pointer'][0]
    listing = program.getListing()
    for addr in find_full_mem_pointers(program=program, align_to=align_to):

        if addr.getOffsetAsBigInteger() % align_to != 0:
            continue
        def_code = listing.getCodeUnitContaining(addr)
        if def_code is not None:
            log.warning("match in code at %s" % addr)
            continue

        def_dat = listing.getDataContaining(addr)
        # skip defined data
        if def_dat is not None:
            continue
        log.info("found data at %s" % addr)
        applyDataTypeAtAddress(addr, ptr_dt)


if __name__ == "__main__":
    identify_unknown_pointers()


