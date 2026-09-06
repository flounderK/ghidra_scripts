#@runtime Jython
"""Tests for ghidra_api.pointer_utils."""

import struct

from __main__ import *

from ghidra_api import pointer_utils as pu
from ghidra_test_support import global_address


class Context(object):
    def __init__(self):
        self.program = currentProgram
        self.utils = pu.createPointerUtils(program=self.program)
        self.g_inner = global_address(self.program, "g_inner")
        self.static_pointer = global_address(self.program, "g_static_inner_pointer")


def setup_module():
    return Context()


def test_pack_code_selection(t, ctx):
    t.equal("64-bit little endian packs as <Q",
            pu.PointerUtils(8, "little").ptr_pack_code, "<Q")
    t.equal("32-bit big endian packs as >I",
            pu.PointerUtils(4, "big").ptr_pack_code, ">I")
    t.check("endian aliases are accepted",
            pu.PointerUtils(8, "le").is_big_endian is False
            and pu.PointerUtils(8, "be").is_big_endian is True)


def test_create_pointer_utils_matches_program(t, ctx):
    t.equal("pointer size comes from the program",
            ctx.utils.ptr_size, ctx.program.getDefaultPointerSize())
    t.equal("endianness comes from the program",
            ctx.utils.is_big_endian, ctx.program.getMemory().isBigEndian())


def test_ptr_ints_from_bytearray_round_trip(t, ctx):
    values = [0x1122334455667788, 0x00000000deadbeef]
    packed = b"".join(struct.pack(ctx.utils.ptr_pack_code, v) for v in values)
    t.equal("packed pointers unpack to the same values",
            list(ctx.utils.ptr_ints_from_bytearray(packed)), values)


def test_ptr_ints_truncates_unaligned_input(t, ctx):
    packed = struct.pack(ctx.utils.ptr_pack_code, 0x41) + b"\x00\x01\x02"
    t.equal("a trailing partial pointer is ignored",
            len(ctx.utils.ptr_ints_from_bytearray(packed)), 1)


def test_gen_pattern_for_pointer_matches_its_own_bytes(t, ctx):
    value = 0x0000555500401000
    pattern = ctx.utils.gen_pattern_for_pointer(value)
    rexp = pu.compile_byte_rexp_pattern(pattern)
    packed = struct.pack(ctx.utils.ptr_pack_code, value)
    t.check("the generated pattern matches the pointer's bytes",
            rexp.search(packed) is not None)
    other = struct.pack(ctx.utils.ptr_pack_code, value + 0x10000)
    t.check("it does not match a different pointer", rexp.search(other) is None)


def test_address_range_pattern_matches_inside_range(t, ctx):
    low, high = 0x00400000, 0x00400200
    rexp = ctx.utils.generate_address_range_rexp(low, high)
    for value in (low, low + 0x80, high):
        packed = struct.pack(ctx.utils.ptr_pack_code, value)
        t.check("0x%x inside [0x%x, 0x%x] matches" % (value, low, high),
                rexp.search(packed) is not None)


def test_address_range_pattern_rejects_outside_range(t, ctx):
    low, high = 0x00400000, 0x00400200
    rexp = ctx.utils.generate_address_range_rexp(low, high)
    for value in (0x00500000, 0x00300000):
        packed = struct.pack(ctx.utils.ptr_pack_code, value)
        t.check("0x%x outside [0x%x, 0x%x] does not match" % (value, low, high),
                rexp.search(packed) is None)


def test_address_range_pattern_escapes_boundary_bytes(t, ctx):
    # the module carries a TODO about backslash escaping of boundary bytes;
    # 0x5c is '\\', the byte that would break an unescaped character class
    low = 0x00005c00
    high = 0x00005cff
    rexp = ctx.utils.generate_address_range_rexp(low, high)
    packed = struct.pack(ctx.utils.ptr_pack_code, low + 0x10)
    t.check("a range whose boundary byte is 0x5c still matches correctly",
            rexp.search(packed) is not None)
    t.check("and does not match a backslash-only value",
            rexp.search(struct.pack(ctx.utils.ptr_pack_code, 0x5c)) is None)


def test_search_for_pointer_finds_a_real_pointer(t, ctx):
    # Search for whatever is actually stored at g_static_inner_pointer, so
    # the check does not depend on how the loader applied relocations --
    # the location holding it must appear in the results.
    t.not_none("fixture provides g_static_inner_pointer", ctx.static_pointer)
    if ctx.static_pointer is None:
        return
    from ghidra_api._compat import get_bytes
    raw = get_bytes(ctx.program, ctx.static_pointer, ctx.utils.ptr_size)
    stored = ctx.utils.ptr_ints_from_bytearray(raw)[0]
    matches = ctx.utils.search_for_pointer(stored)
    t.check("the stored pointer value is found in memory", len(matches) > 0,
            "found %d matches for 0x%x" % (len(matches), stored))
    t.contains("the location holding it is among the matches",
               [str(a) for a in matches], str(ctx.static_pointer))
