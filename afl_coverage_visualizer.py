# Visualize the coverage from an afl++ bitmap in ghidra.
# Generate a showmap file with
# `afl-showmap -C -i <afl-out-dir> -o showmap -- <fuzzed-binary>`
# NOTE: it is possible for certain blocks at the start of your binary to be
# missed if afl is running in persistent mode, so a red block at the start of
# main is likely to be valida
#@author Clifton Wolfe

import ghidra
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.symbol import SymbolType
from collections import namedtuple, defaultdict
import os
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
# but so far it seems to start here
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


def get_code_block(address):
    func = getFunctionContaining(address)
    if not func:
        return None
    block_model = BasicBlockModel(currentProgram)
    addresses = func.getBody()
    code_blocks = list(block_model.getCodeBlocksContaining(addresses,
                                                           monitor))
    for code_block in code_blocks:
        if code_block.contains(address):
            return code_block
    return None


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


def get_code_block_sources(code_block):
    """
    block.SimpleSourceReferenceIterator is not iterable
    """
    sources = []
    source_iterator = code_block.getSources(monitor)
    while source_iterator.hasNext():
        sources.append(source_iterator.next())
    return sources


def get_code_block_dests(code_block):
    """
    block.SimpleSourceReferenceIterator is not iterable
    """
    dests = []
    dest_iterator = code_block.getDestinations(monitor)
    while dest_iterator.hasNext():
        dests.append(dest_iterator.next())
    return dests


class BlockHighlighter:
    """
    Class for hightlighting basic blocks
    """
    def __init__(self):
        self.hightlighted_block_record = []
        self.listing = currentProgram.getListing()

    def highlight_code_block_of_address(self, address,
                                        color=COLOR_VISITED):
        bb = get_code_block(address)
        self.highlight_code_block(bb)

    def highlight_code_block(self, code_block, color=COLOR_VISITED):
        for address_range in code_block.addressRanges:
            address_set = AddressSet(address_range)
            setBackgroundColor(address_set, color)
        # save record of this highlight so it can be
        # undone later
        self.hightlighted_block_record.append(code_block)


class BlockFlowTracer:
    def __init__(self, visited_blocks):
        self._traced_blocks = set()
        self._visited_blocks = set(visited_blocks)

    def find_unconditional_source_blocks(self, code_block):
        curr_code_block = code_block
        unconditional_source_blocks = set()
        self._visited_blocks.add(code_block)
        while True:
            block_sources = get_code_block_sources(curr_code_block)
            if len(block_sources) != 1 or curr_code_block in unconditional_source_blocks:
                break
            src = block_sources[0]
            src_block = src.getSourceBlock()
            unconditional_source_blocks.add(src_block)
            curr_code_block = src_block
        self._visited_blocks.update(unconditional_source_blocks)
        return unconditional_source_blocks

    def find_unconditional_dest_blocks(self, code_block):
        curr_code_block = code_block
        unconditional_dest_blocks = set()
        self._visited_blocks.add(code_block)
        while True:
            block_dests = get_code_block_dests(curr_code_block)
            if len(block_dests) != 1 or curr_code_block in unconditional_dest_blocks:
                break
            dest = block_dests[0]
            dest_block = dest.getDestinationBlock()
            unconditional_dest_blocks.add(dest_block)
            curr_code_block = dest_block
        self._visited_blocks.update(unconditional_dest_blocks)
        return unconditional_dest_blocks

    def get_unconditionally_visited_blocks(self, code_block):
        all_visited_blocks = set()
        usb = self.find_unconditional_source_blocks(code_block)
        udb = self.find_unconditional_dest_blocks(code_block)
        all_visited_blocks.update(usb)
        all_visited_blocks.update(udb)
        all_visited_blocks.add(code_block)
        return all_visited_blocks

    def get_all_unconditionally_visited_blocks(self):
        # copy so that blocks don't get processed twice
        # during this process, as visited_blocks gets updated
        visited_blocks_copy = list(self._visited_blocks)
        all_visited_blocks = set(visited_blocks_copy)
        for visited_block in visited_blocks_copy:
            uvb = self.get_unconditionally_visited_blocks(visited_block)
            all_visited_blocks.update(uvb)
        return all_visited_blocks


def highlight_visited_and_unvisited_blocks(all_visited_blocks, unreached):
    """
    Generic function for highlighting all of the blocks that were visited
    and unvisited. Also does a little bit of "analysis" to try to improve
    results slightly
    """
    bbh = BlockHighlighter()
    # Find blocks that must be unconditionally reached
    v_bft = BlockFlowTracer(all_visited_blocks)
    all_blocks_to_highlight = v_bft.get_all_unconditionally_visited_blocks()

    for block in unreached:
        bbh.highlight_code_block(block, COLOR_UNVISITED)

    for block in all_blocks_to_highlight:
        bbh.highlight_code_block(block, COLOR_VISITED)


def hightlight_sancov_visited_code_blocks():
    """
    Highlight blocks based on sancov pc guards. Only works for binaries
    built with afl
    """
    showmap_file = askFile("showmap File",
                           "Path to a file output from afl-showmap")
    showmap_filepath = showmap_file.toString()

    showmap_indices = parse_indices_from_showmap_output(showmap_filepath)
    showmap_offsets = set([showmap_index_to_pc_guard_offset(i) for i in showmap_indices])
    pc_guard_refs = get_pc_guard_refs()
    unreached_code_blocks = []
    all_visited_blocks = []
    # TODO: these can likely be optimized a bit
    for pc_guard_ref in pc_guard_refs:
        code_block = get_code_block(pc_guard_ref.ref.fromAddress)
        # pick out the ones that are not visited
        if pc_guard_ref.offset not in showmap_offsets:
            unreached_code_blocks.append(code_block)
            continue

        all_visited_blocks.append(code_block)

    all_blocks_to_highlight = all_visited_blocks
    highlight_visited_and_unvisited_blocks(all_blocks_to_highlight,
                                           unreached_code_blocks)


def all_child_filepaths_gen(dir_path):
    """
    Get all of the files under the dir path
    """
    for dirpath, dirnames, filenames in os.walk(dir_path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            yield filepath


class QemuAsmAnalyzer:
    """
    A class for Assisting with the analysis of qemu asm logs.
    Helps to determine if current program's base changes
    """
    def __init__(self):
        self.symb_history = defaultdict(list)
        self.symb_rexp = re.compile('IN: ([^\n]+)\n(0x[a-f0-9]+)',
                                    re.MULTILINE | re.DOTALL)
        self.first_block_addr_rexp = re.compile('IN:[^\n]+\n(0x[a-f0-9]+):',
                                    re.MULTILINE | re.DOTALL)
        sm = currentProgram.getSymbolTable()
        self.useful_symbols = {i.name: i.getAddress().getOffset()
                               for i in sm.getSymbolIterator()
                               if i.isExternalEntryPoint() and
                               i.symbolType == SymbolType.FUNCTION}

    def get_binary_base_from_symbols(self, qemu_in_asm_log):
        """
        Get the base of the binary using the symbols that appear in
        qemu log
        """
        current_base_int = currentProgram.getImageBase().getOffset()
        for m in re.finditer(self.symb_rexp, qemu_in_asm_log):
            log_symbol, address_str = m.groups()
            log_address = int(address_str, 16)
            known_addr = self.useful_symbols.get(log_symbol)
            # if the symbol doesn't appear in ghidra, it is likely from the
            # wrong binary, skip it
            if known_addr is None:
                continue

            # symbol matched, but is probably a dupicate symbol that exists
            # in multiple binaries. Only keep ones that appear to have come
            # from this binary
            if (known_addr & 0xfff) != (log_address & 0xfff):
                continue

            # ghidra will add a dummy base address if the executable is PIE,
            # so remove that to get the offset
            known_offset = known_addr - current_base_int
            binary_base = log_address - known_offset
            return binary_base

        return None

    def get_binary_base(self, qemu_in_asm_log):
        """
        Try to get the base of the binary through a few different methods
        """
        maybe_base = self.get_binary_base_from_symbols(qemu_in_asm_log)
        if maybe_base:
            return maybe_base

    def get_first_address_of_each_block(self, qemu_in_asm_log):
        """
        yield the first address in each block.
        """
        for m in re.finditer(self.first_block_addr_rexp, qemu_in_asm_log):
            yield int(m.groups()[0], 16)

    def parse_qemu_asm_visited_addresses(self, file_contents):
        """
        More extensive, but on larger binaries the output could be messive
        """
        rexp = re.compile("(0x[a-f0-9]+):")
        for m in re.finditer(rexp, file_contents):
            address_str = m.groups()[0]
            address = int(address_str, 16)
            yield address


def highlight_qemu_visited_code_blocks():
    dir_obj = askDirectory("Path to output from gather_qemu_coverage_data.sh",
                           "select")

    # this is set as the base address in
    # ASSUMED_BASE_ADDRESS = 0x1800000
    dir_path = dir_obj.toString()
    all_visited_blocks = set()
    current_image_base_int = currentProgram.getImageBase().getOffset()
    qaa = QemuAsmAnalyzer()
    for path in all_child_filepaths_gen(dir_path):
        with open(path, "r") as f:
            file_contents = f.read()
        binary_base_address_in_log = qaa.get_binary_base(file_contents)
        for log_addr in qaa.get_first_address_of_each_block(file_contents):
            # adjust the address so that it matches up with what is in ghidra
            log_offset = (log_addr - binary_base_address_in_log)
            ghidra_addr = toAddr(log_offset + current_image_base_int)
            code_block = get_code_block(ghidra_addr)
            if code_block:
                all_visited_blocks.append(code_block)

    highlight_visited_and_unvisited_blocks(list(all_visited_blocks), [])


if __name__ == "__main__":
    # hightlight_sancov_visited_code_blocks()
    highlight_qemu_visited_code_blocks()
