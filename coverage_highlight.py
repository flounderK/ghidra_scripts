# Visualize the coverage from a list of addresses
#@runtime Jython
#@author Clifton Wolfe

import ghidra
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import AddressSet
from ghidra.program.model.address import AddressRangeImpl
import os
import re

from java.awt import Color

from __main__ import *

COLOR_DEFAULT = Color(255, 255, 255)  # white
COLOR_VISITED = Color(137, 207, 240)  # light blue
COLOR_UNVISITED = Color(178, 34, 34)  # dark red


def get_instruction_addr_set_for_addresses(addresses):
    addr_set = AddressSet()
    listing = currentProgram.getListing()
    for addr in addresses:
        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            continue
        addr_range = AddressRangeImpl(cu.minAddress, cu.maxAddress)
        addr_set.add(addr_range)
    return addr_set


def get_basic_block_addr_set_for_addresses(addresses):
    addr_set = AddressSet()
    bbm = BasicBlockModel(currentProgram)
    code_blocks = list(bbm.getCodeBlocksContaining(addresses,
                                                   monitor))
    for block in code_blocks:
        for addr_range in block.addressRanges:
            addr_set.add(addr_range)
    return addr_set


def entrypoint():
    file = askFile("File",
                   "Path to a file containing visited addresses")
    filepath = file.toString()
    with open(filepath, "r") as f:
        c = f.read()

    rexp = re.compile("(0x[a-fA-F0-9]+)")
    addrs = [int(m.groups()[0], 16) for m in re.finditer(rexp, c)]

    choices = askChoices("Coverage Highlighter",
                         "Select how you would like to highlight coverage",
                         ["instruction",
                          "basic_block"],
                         ["Instruction-level granularity",
                          "Basic block-level granularity"])
    if "instruction" in choices:
        addr_set = get_instruction_addr_set_for_addresses(addrs)
    elif "basic_block" in choices:
        addr_set = get_basic_block_addr_set_for_addresses(addrs)

    setBackgroundColor(addr_set, COLOR_VISITED)


if __name__ == "__main__":
    entrypoint()
