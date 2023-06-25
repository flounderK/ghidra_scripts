# Try to visualize the coverage from an afl++ bitmap in ghidra
# generate a showmap file with
# `afl-showmap -C -i <afl-out-dir> -o showmap -- <fuzzed-binary>`
#@author Clifton Wolfe

import ghidra
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import AddressSet
from collections import namedtuple
import re

from java.awt import Color

from __main__ import *

# offset is used here instead of index because the the values stored
# in each of the uint32_t's in the __sancov_guards section is an
# index value, but these indexes do not start with zero so it would
# get confusing to have two different index values in the object
SanCovPCGuardRef = namedtuple("SanCovPCGuardRef", ["ref",
                                                   "calling_function",
                                                   "offset"])

SANCOV_PC_GUARD_VALUE_SIZE = 4
# this might change in different versions or with different builds,
# but so far it seems to start at 6
SANCOV_PC_GUARD_START_INDEX = 6
COLOR_DEFAULT = Color(255, 255, 255)  # white
COLOR_VISITED = Color(137, 207, 240)  # light blue
COLOR_UNVISITED = Color(178, 34, 34)  # dark red


def get_pc_guard_refs():
    """
    This function finds the __sancov_guards section in memory and
    returns a list of SanCovPCGuardRefs that are referred to by
    code in the currentProgram
    """
    nsm = currentProgram.getNamespaceManager()
    global_namespace = nsm.getGlobalNamespace()

    start_sym = getSymbol("__start___sancov_guards", global_namespace)
    stop_sym = getSymbol("__stop___sancov_guards", global_namespace)

    if start_sym is None or stop_sym is None:
        print("Currently only binaries built with sancov pc guards are supported")
        exit(1)

    sancov_guards_addr = start_sym.getAddress()
    sancov_guards_size = stop_sym.getAddress().subtract(sancov_guards_addr)
    pc_guard_refs = []
    for offset in range(0, sancov_guards_size,
                        SANCOV_PC_GUARD_VALUE_SIZE):
        curr_addr = sancov_guards_addr.add(offset)
        # each location should really only be referenced once,
        # but the first few entries might have an extra
        valid_ref_found = False
        for ref in getReferencesTo(curr_addr):
            calling_function = getFunctionContaining(ref.fromAddress)
            # ignore references that are data references only
            if calling_function is None:
                continue
            # ignore things related to sancov, which will probably refer
            # to the first and last entry for initialization
            if calling_function.name.startswith("sancov"):
                continue

            valid_ref_found = True
            break

        if valid_ref_found is False:
            continue

        sancov_guard_ref = SanCovPCGuardRef(ref, calling_function,
                                            offset)

        pc_guard_refs.append(sancov_guard_ref)
    return pc_guard_refs


class BasicBlockHighlighter:
    """
    Class for hightlighting basic blocks
    """
    def __init__(self):
        self.hightlighted_block_record = set()
        self.listing = currentProgram.getListing()

    def get_basic_block(self, address):
        # cu = self.listing.getCodeUnitContaining(address)
        func = getFunctionContaining(address)
        block_model = BasicBlockModel(currentProgram)
        addresses = func.getBody()
        code_blocks = list(block_model.getCodeBlocksContaining(addresses,
                                                               monitor))
        for code_block in code_blocks:
            if code_block.contains(address):
                return code_block
        return None

    def highlight_basic_block_of_address(self, address,
                                         color=COLOR_VISITED):
        bb = self.get_basic_block(address)
        for address_range in bb.addressRanges:
            address_set = AddressSet(address_range)
            setBackgroundColor(address_set, color)
        # save record of this highlight so it can be
        # undone later
        self.hightlighted_block_record.add(address)


def parse_indices_from_showmap_output(filepath):
    """
    return the index value from a file output by afl-showmap
    """
    with open(filepath, "r") as f:
        content = f.read()

    rexp = re.compile(r"(\d+):\d+")
    indices = []
    for m in re.finditer(rexp, content):
        index_str = m.groups()[0]
        index = int(index_str)
        indices.append(index)

    return indices


def showmap_index_to_pc_guard_offset(index):
    return (index - SANCOV_PC_GUARD_START_INDEX) * SANCOV_PC_GUARD_VALUE_SIZE


def pc_guard_offset_to_showmap_index(offset):
    return (offset // SANCOV_PC_GUARD_VALUE_SIZE) + SANCOV_PC_GUARD_START_INDEX


def hightlight_sancov_visited_basic_blocks():
    """
    Currently the main functionality of the script.
    """
    showmap_file = askFile("showmap File",
                           "Path to a file output from afl-showmap")
    showmap_filepath = showmap_file.toString()

    showmap_indices = parse_indices_from_showmap_output(showmap_filepath)
    showmap_offsets = set([showmap_index_to_pc_guard_offset(i) for i in showmap_indices])
    pc_guard_refs = get_pc_guard_refs()
    bbh = BasicBlockHighlighter()
    unused_pc_guard_refs = []
    # TODO: these can likely be optimized a bit
    for pc_guard_ref in pc_guard_refs:
        addr = pc_guard_ref.ref.fromAddress
        if pc_guard_ref.offset not in showmap_offsets:
            unused_pc_guard_refs.append(pc_guard_ref)
            continue
        bbh.highlight_basic_block_of_address(addr, COLOR_VISITED)

    for pc_guard_ref in unused_pc_guard_refs:
        addr = pc_guard_ref.ref.fromAddress
        bbh.highlight_basic_block_of_address(addr, COLOR_UNVISITED)


if __name__ == "__main__":
    hightlight_sancov_visited_basic_blocks()
