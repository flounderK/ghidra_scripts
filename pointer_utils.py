# Utility Class for interacting with pointers
#@author Clifton Wolfe
#@category Utils

import ghidra
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import GenericAddress, Address

import string
import re
import struct
# makes it easier for dev and testing
from __main__ import *


class PointerUtils:
    def __init__(self, program=None):
        if program is None:
            program = currentProgram
        self.addr_fact = program.getAddressFactory()
        self.addr_space = self.addr_fact.getDefaultAddressSpace()
        self.ptr_size = self.addr_space.getPointerSize()
        self.mem = program.getMemory()
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
        self.ptr_pack_code = self.pack_endian + self.ptr_pack_sym
        self.minimum_addr_int, self.maximum_addr_int = self.get_memory_bounds()
        self.minimum_addr_addr = toAddr(self.minimum_addr_int)
        self.maximum_addr_addr = toAddr(self.maximum_addr_int)

    def get_memory_bounds(self, excluded_memory_block_names=["tdb"]):
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
        # create a character class that will match the largest changing byte
        boundary_byte_pattern = b"[\\%s-\\%s]" % (bytearray([boundary_byte_lower]),
                                                  bytearray([boundary_byte_upper]))

        address_pattern = b''
        single_address_pattern = b''
        if self.mem.isBigEndian() is False:
            packed_addr = struct.pack(self.ptr_pack_code, minimum_addr)
            single_address_pattern = b''.join([wildcard_pattern*wildcard_bytes,
                                               boundary_byte_pattern,
                                               packed_addr[byte_count:]])
        else:
            packed_addr = struct.pack(self.ptr_pack_code, minimum_addr)
            single_address_pattern = b''.join([packed_addr[:byte_count],
                                               boundary_byte_pattern,
                                               wildcard_pattern*wildcard_bytes])

        # empty_addr = struct.pack(self.ptr_pack_sym, 0)

        address_pattern = b"(%s)" % single_address_pattern
        return address_pattern

    def generate_address_range_rexp(self, minimum_addr, maximum_addr):
        """
        Generate a regular expression that can match on any value between
        the provided minimum addr and maximum addr
        """
        address_pattern = self.generate_address_range_pattern(minimum_addr, maximum_addr)
        address_rexp = re.compile(address_pattern, re.DOTALL | re.MULTILINE)
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

    def search_for_pointer(self, pointer):
        """
        Find all locations where a specific pointer is embedded in memory
        """
        if isinstance(pointer, GenericAddress):
            pointer = pointer.getOffsetAsBigInteger()

        pointer_bytes = struct.pack(self.ptr_pack_code, pointer)
        pointer_pattern = re.escape(pointer_bytes)
        address_rexp = re.compile(pointer_pattern, re.DOTALL | re.MULTILINE)
        match_addrs, _ = self.search_memory_for_rexp(address_rexp)
        return match_addrs

    def search_memory_for_rexp(self, rexp, save_match_objects=True):
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

