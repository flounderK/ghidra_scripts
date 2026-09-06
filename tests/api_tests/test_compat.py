#@runtime Jython
"""Tests for ghidra_api._compat, the Jython/CPython compatibility shims."""

from __main__ import *

from ghidra_api import _compat
from ghidra_api._compat import CAUGHT_ERRORS
from ghidra_test_support import get_function, global_address


class ThrowingCommand(object):
    """Duck-typed Ghidra command whose applyTo raises a Java exception."""

    def __init__(self, program):
        self._program = program

    def getName(self):
        return "deliberately failing test command"

    def applyTo(self, program):
        # a genuine Java exception, not a Python one
        self._program.getMemory().getByte(
            self._program.getAddressFactory().getAddress("0xfffffff0"))


class Context(object):
    def __init__(self):
        self.program = currentProgram
        self.leaf = get_function(self.program, "leaf")


def setup_module():
    return Context()


def test_resolve_program(t, ctx):
    t.equal("an explicit program is returned unchanged",
            _compat.resolve_program(ctx.program), ctx.program)
    t.equal("None resolves to currentProgram",
            _compat.resolve_program(None), ctx.program)


def test_resolve_monitor(t, ctx):
    t.not_none("None resolves to a usable monitor", _compat.resolve_monitor(None))
    sentinel = _compat.resolve_monitor(None)
    t.equal("an explicit monitor is returned unchanged",
            _compat.resolve_monitor(sentinel), sentinel)


def test_to_addr_accepts_int_and_string(t, ctx):
    entry = ctx.leaf.getEntryPoint()
    from_int = _compat.to_addr(ctx.program, entry.getOffset())
    from_str = _compat.to_addr(ctx.program, str(entry))
    t.equal("an integer offset resolves to the same address", from_int, entry)
    t.equal("a string offset resolves to the same address", from_str, entry)


def test_get_function_at_and_containing(t, ctx):
    entry = ctx.leaf.getEntryPoint()
    t.equal("get_function_at finds the function at its entry",
            _compat.get_function_at(ctx.program, entry), ctx.leaf)
    inside = entry.next()
    t.equal("get_function_containing finds it from inside the body",
            _compat.get_function_containing(ctx.program, inside), ctx.leaf)
    t.equal("get_function_at returns None away from an entry point",
            _compat.get_function_at(ctx.program, inside), None)


def test_get_memory_blocks(t, ctx):
    blocks = _compat.get_memory_blocks(ctx.program)
    t.check("the program has memory blocks", len(blocks) > 0)
    t.check("blocks are returned as a list", isinstance(blocks, list))


def test_get_bytes(t, ctx):
    entry = ctx.leaf.getEntryPoint()
    data = _compat.get_bytes(ctx.program, entry, 4)
    t.equal("the requested number of bytes is returned", len(data), 4)
    expected = [ctx.program.getMemory().getByte(entry.add(i)) for i in range(4)]
    t.equal("the bytes match memory", [b for b in data], expected)


def test_get_references(t, ctx):
    entry = ctx.leaf.getEntryPoint()
    to_refs = list(_compat.get_references_to(ctx.program, entry))
    t.check("leaf has references to it", len(to_refs) > 0)
    from_refs = list(_compat.get_references_from(ctx.program, entry))
    t.check("references from an address are returned as a sequence",
            isinstance(from_refs, list))


def test_run_command_success(t, ctx):
    from ghidra.app.cmd.label import AddLabelCmd
    from ghidra.program.model.symbol import SourceType
    address = global_address(ctx.program, "g_scratch")
    t.not_none("fixture provides a scratch global", address)
    if address is None:
        return
    command = AddLabelCmd(address, "compat_test_label", SourceType.USER_DEFINED)
    t.check("a valid command reports success",
            _compat.run_command(ctx.program, command))
    names = [s.getName() for s in ctx.program.getSymbolTable().getSymbols(address)]
    t.contains("the command's effect is visible", names, "compat_test_label")


def test_run_command_closes_transaction_on_failure(t, ctx):
    # `except Exception` does not catch Java exceptions under Jython, so this
    # used to leave the transaction open forever
    before = str(ctx.program.getCurrentTransactionInfo())
    raised = False
    try:
        _compat.run_command(ctx.program, ThrowingCommand(ctx.program))
    except CAUGHT_ERRORS:
        raised = True
    t.check("a failing command propagates its error", raised)
    after = str(ctx.program.getCurrentTransactionInfo())
    t.equal("no transaction is left open after a failing command", after, before)
