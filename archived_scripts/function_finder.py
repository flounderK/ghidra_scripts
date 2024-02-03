# Search for function prologues by providing a set of bytes to search
# for
#@author Clifton Wolfe

import ghidra
import re
import binascii
from __main__ import *

def create_character_class_byte_range(start, end):
    """
    Create a pre-escaped byte pattern that will work in re
    """
    return b"\\%s-\\%s" % (bytearray([start]), bytearray([end]))


def _gen_xtensa_entry_pattern():
    """
    Create a pattern for the xtensa ENTRY instruction
    """
    character_class_inner = b''
    start_add, end_add = 1, 0xf
    for i in range(0, 256, 0x10):
        new_range = create_character_class_byte_range(start_add+i,
                                                      end_add+i)
        character_class_inner += new_range

    pattern = b'\x36[%s].' % character_class_inner
    return pattern


def xtensa_entry_rexp_provider():
    rexp = re.compile(_gen_xtensa_entry_pattern(),
                      re.DOTALL | re.MULTILINE)
    return rexp


def single_pattern_rexp_provider():
    # using askBytes can result in an array containing a signed int, which
    # can't be processed correctly as a byte value
    byte_vals_from_user = askString("Enter bytes that mark a function entry",
                                    "search")
    byte_vals = binascii.unhexlify(byte_vals_from_user.replace(' ', ''))

    # python 2 requires bytearray to change to actual bytes
    byte_pattern = bytes(bytearray(list(byte_vals)))
    escaped_byte_pattern = re.escape(byte_pattern)

    byte_rexp = re.compile(escaped_byte_pattern,
                           re.MULTILINE | re.DOTALL)


def func_search(rexp_provider):
    byte_rexp = rexp_provider()

    memory_blocks = list(getMemoryBlocks())

    # maybe add a filter here
    search_memory_blocks = memory_blocks

    for m_block in search_memory_blocks:
        if not m_block.isInitialized():
            continue
        region_start = m_block.getStart()
        region_start_int = region_start.getOffset()
        search_bytes = getBytes(region_start, m_block.getSize())
        iter_gen = re.finditer(byte_rexp, search_bytes)
        for m in iter_gen:
            addr = region_start.add(m.start())
            func = getFunctionContaining(addr)
            if func is not None:
                continue
            disassemble(addr)
            createFunction(addr, "FUN_%s" % str(addr))


if __name__ == "__main__":
    func_search(single_pattern_rexp_provider)
