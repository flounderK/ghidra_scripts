#@runtime Jython
"""Tests for ghidra_api.raw_pcode_utils."""

from __main__ import *
from ghidra.program.model.pcode import PcodeOp

from ghidra_api import raw_pcode_utils as rpu
from ghidra_test_support import get_function

CALL_OPCODES = [PcodeOp.CALL]


class Context(object):
    def __init__(self):
        self.program = currentProgram
        self.top = get_function(self.program, "top_caller")
        self.leaf = get_function(self.program, "leaf")


def setup_module():
    return Context()


def test_get_raw_pcode_for_func(t, ctx):
    ops = rpu.get_raw_pcode_for_func(ctx.top)
    t.check("raw pcode is produced for a function", len(ops) > 0,
            "found %d ops" % len(ops))
    t.check("top_caller contains CALL ops",
            any(op.getOpcode() == PcodeOp.CALL for op in ops))


def test_get_raw_pcode_is_flat(t, ctx):
    ops = rpu.get_raw_pcode_for_func(ctx.leaf)
    t.check("result is a flat list of pcode ops",
            all(hasattr(op, "getOpcode") for op in ops))


def test_get_funcs_to_op_addrs(t, ctx):
    mapping = rpu.get_funcs_to_op_addrs(CALL_OPCODES)
    names = set(f.getName() for f in mapping if f is not None)
    t.contains("a function containing calls is reported", names, "top_caller")
    for func, addresses in mapping.items():
        if func is None:
            continue
        t.check("addresses lie inside their function (%s)" % func.getName(),
                all(func.getBody().contains(a) for a in addresses))
        break


def test_get_func_op_freq_list_is_sorted(t, ctx):
    freq = rpu.get_func_op_freq_list(CALL_OPCODES)
    t.check("a frequency list is produced", len(freq) > 0)
    counts = [count for _, count in freq]
    t.equal("the list is sorted by descending frequency",
            counts, sorted(counts, reverse=True))


def test_get_addr_set_for_ops_in_func(t, ctx):
    addr_set = rpu.get_addr_set_for_ops_in_func(ctx.top, CALL_OPCODES)
    t.not_none("an address set is returned", addr_set)
    if addr_set is None:
        return
    t.check("the set is non-empty for a function containing calls",
            not addr_set.isEmpty())
    t.check("every selected address lies inside the function",
            ctx.top.getBody().contains(addr_set.getMinAddress()))
