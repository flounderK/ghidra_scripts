# Utility Class for interacting with pointers. To get an instance of the class,
# use createPointerUtils
#@author Clifton Wolfe
#@category Utils

import ghidra
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import GenericAddress, Address

import string
import re
import struct
# makes it easier for dev and testing
from __main__ import *


def compile_byte_rexp_pattern(pattern):
    """
    Compile a pattern so that it can be searched in a series of bytes
    """
    return re.compile(pattern, re.DOTALL | re.MULTILINE)


def get_memory_bounds(excluded_memory_block_names=["tdb"]):
    """
    Try to identify the bounds of memory that is currently mapped in.
    Some standard memory blocks (like `tdb` for microsoft binaries)
    are mapped in at ridiculous addresses (like 0xff00000000000000).
    If a memory block is mapped into this program
    """
    minimum_addr = 0xffffffffffffffff
    maximum_addr = 0
    memory_blocks = list(getMemoryBlocks())
    for m_block in memory_blocks:
        # tdb is placed at a very large address that is well outside
        # of the loaded range for most executables
        if m_block.name in excluded_memory_block_names:
            continue
        start = m_block.getStart().getOffset()
        end = m_block.getEnd().getOffset()
        if start < minimum_addr:
            minimum_addr = start
        if end > maximum_addr:
            maximum_addr = end
    return minimum_addr, maximum_addr


def search_memory_for_rexp(rexp, save_match_objects=True):
    """
    Given a regular expression, search through all of the program's
    memory blocks for it and return a list of addresses where it was found,
    as well as a list of the match objects. Set `save_match_objects` to
    False if you are searching for exceptionally large objects and
    don't want to keep the matches around
    """
    memory_blocks = list(getMemoryBlocks())
    search_memory_blocks = memory_blocks
    # TODO: maybe implement filters for which blocks get searched
    # filter out which memory blocks should actually be searched
    # search_memory_blocks = [i for i in search_memory_blocks
    #                         if i.getPermissions() == i.READ]
    # if additional_search_block_filter is not None:
    #     search_memory_blocks = [i for i in search_memory_blocks if
    #                             additional_search_block_filter(i) is True]
    all_match_addrs = []
    all_match_objects = []
    for m_block in search_memory_blocks:
        if not m_block.isInitialized():
            continue
        region_start = m_block.getStart()
        region_start_int = region_start.getOffset()
        search_bytes = getBytes(region_start, m_block.getSize())
        iter_gen = re.finditer(rexp, search_bytes)
        match_count = 0
        # hacky loop over matches so that the recursion limit can be caught
        while True:
            try:
                m = next(iter_gen)
            except StopIteration:
                # this is where the loop is normally supposed to end
                break
            except RuntimeError:
                # this means that recursion went too deep
                print("match hit recursion limit on match %d" % match_count)
                break
            match_count += 1
            location_addr = region_start.add(m.start())
            all_match_addrs.append(location_addr)
            if save_match_objects:
                all_match_objects.append(m)
    return all_match_addrs, all_match_objects


def batch_pattern_memory_search(patterns, batchsize=100, save_match_objects=True):
    """
    Works similar to search_memory_for_rexp, but supports running a list of patterns in batches
    so that python doesn't have to run a 500,000 character regular expression.
    """
    def batch(it, sz):
        for i in range(0, len(it), sz):
            yield it[i:i+sz]

    all_match_addrs = []
    all_match_objects = []
    for pattern_batch in batch(patterns, batchsize):
        joined_pattern = b'(%s)' % b'|'.join(pattern_batch)
        rexp = compile_byte_rexp_pattern(joined_pattern)
        match_addrs, match_obj = search_memory_for_rexp(rexp, save_match_objects=save_match_objects)
        all_match_addrs.extend(match_addrs)
        all_match_objects.extend(match_obj)
    return all_match_addrs, all_match_objects


class PointerUtils:
    def __init__(self, ptr_size=8, endian="little"):
        self.ptr_size = ptr_size
        if endian.lower() in ["big", "msb", "be"]:
            self.endian = "big"
            self.is_big_endian = True
        elif endian.lower() in ["little", "lsb", "le"]:
            self.endian = "little"
            self.is_big_endian = False

        self.ptr_pack_sym = ""
        if self.ptr_size == 4:
            self.ptr_pack_sym = "I"
        elif self.ptr_size == 8:
            self.ptr_pack_sym = "Q"

        self.pack_endian = ""
        if self.is_big_endian is True:
            self.pack_endian = ">"
        else:
            self.pack_endian = "<"
        self.ptr_pack_code = self.pack_endian + self.ptr_pack_sym

    def generate_address_range_pattern(self, minimum_addr, maximum_addr):
        """
        Generate a regular expression pattern that can be used to match
        the bytes for an address between minimum_addr and maximum_addr
        (inclusive). This works best for small ranges, and will break
        somewhat if there are non-contiguous memory blocks, but it works
        well enough for most things
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
        if boundary_byte_upper < boundary_byte_lower:
            boundary_byte_upper, boundary_byte_lower = boundary_byte_lower, boundary_byte_upper
        # create a character class that will match the largest changing byte
        lower_byte = bytearray([boundary_byte_lower])
        upper_byte = bytearray([boundary_byte_upper])
        # re.escape breaks depending on version of python,
        # converting bytes to strings. instead, manually escape
        # TODO: add a test case for this to make sure that python
        # TODO: isn't matching against the backslash for the end byte
        escaped_lower_byte = re.escape(lower_byte)
        escaped_lower_byte = bytearray(escaped_lower_byte)
        escaped_upper_byte = re.escape(upper_byte)
        escaped_upper_byte = bytearray(escaped_upper_byte)
        boundary_byte_pattern = b"[%s-%s]" % (escaped_lower_byte,
                                              escaped_upper_byte)
        address_pattern = b''
        single_address_pattern = b''
        if self.is_big_endian is False:
            packed_addr = struct.pack(self.ptr_pack_code, minimum_addr)
            single_address_pattern = b''.join([wildcard_pattern*wildcard_bytes,
                                               boundary_byte_pattern,
                                               packed_addr[byte_count:]])
        else:
            packed_addr = struct.pack(self.ptr_pack_code, minimum_addr)
            single_address_pattern = b''.join([packed_addr[:byte_count],
                                               boundary_byte_pattern,
                                               wildcard_pattern*wildcard_bytes])
        address_pattern = b"(%s)" % single_address_pattern
        return address_pattern

    def generate_address_range_rexp(self, minimum_addr, maximum_addr):
        """
        Generate a regular expression that can match on any value between
        the provided minimum addr and maximum addr
        """
        address_pattern = self.generate_address_range_pattern(minimum_addr, maximum_addr)
        address_rexp = compile_byte_rexp_pattern(address_pattern)
        return address_rexp

    def ptr_ints_from_bytearray(self, bytarr):
        """
        Returns a tuple of poitner-sized ints unpacked from the provided
        bytearray
        """
        bytarr = bytearray(bytarr)
        # truncate in case the bytarray isn't aligned to ptr size
        fit_len = len(bytarr) // self.ptr_size
        pack_code = "%s%d%s" % (self.pack_endian, fit_len, self.ptr_pack_sym)
        return struct.unpack_from(pack_code, bytarr)

    def gen_pattern_for_pointer(self, pointer):
        """
        Generate a regular expression pattern for a pointer
        """
        if isinstance(pointer, GenericAddress):
            pointer = pointer.getOffsetAsBigInteger()

        pointer_bytes = struct.pack(self.ptr_pack_code, pointer)
        pointer_pattern = re.escape(pointer_bytes)
        return pointer_pattern

    def search_for_pointer(self, pointer):
        """
        Find all locations where a specific pointer is embedded in memory
        """
        pointer_pattern = self.gen_pattern_for_pointer(pointer)
        address_rexp = compile_byte_rexp_pattern(pointer_pattern)
        match_addrs, _ = search_memory_for_rexp(address_rexp)
        return match_addrs


def createPointerUtils(program=None, ptr_size=None, endian=None):
    if program is None:
        program = currentProgram
    if ptr_size is None:
        ptr_size = program.getDefaultPointerSize()
    if endian is None:
        mem = program.getMemory()
        if mem.isBigEndian():
            endian = "big"
        else:
            endian = "little"
    pu = PointerUtils(ptr_size, endian)
    return pu
