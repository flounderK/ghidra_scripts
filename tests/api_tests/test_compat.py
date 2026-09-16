"""Tests for ghidra_api._compat, the Jython/CPython compatibility shims."""

from ghidra_api._compat import resolve_monitor, resolve_program

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
        self.program = resolve_program(None)
        self.leaf = get_function(self.program, "leaf")


def setup_module():
    return Context()


def test_resolve_program(t, ctx):
    t.equal("an explicit program is returned unchanged",
            _compat.resolve_program(ctx.program), ctx.program)
    t.equal("None resolves to the script's current program",
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


# --- dual-runtime plumbing --------------------------------------------------
# These are the shims that let the package run under both Jython and PyGhidra.
# They are the parts most likely to break silently on one runtime only, so each
# is checked here rather than being taken on trust.

def test_flat_api_is_discoverable_from_an_imported_module(t, ctx):
    """The whole point: this file is imported, not the running script.

    Under Jython the flat API is on __main__; under PyGhidra it is reached by
    walking out to the script's frame. Either way it has to be found from here.
    """
    api = _compat.flat_api()
    t.not_none("a script context is discoverable from a module", api)
    t.equal("and its currentProgram is this program",
            getattr(api, "currentProgram", None), ctx.program)


def test_set_script_context_overrides_discovery(t, ctx):
    class Stub(object):
        currentProgram = "sentinel program"
        monitor = "sentinel monitor"

    try:
        _compat.set_script_context(Stub())
        t.equal("an explicit context is used for the program",
                _compat.resolve_program(None), "sentinel program")
        t.equal("and for the monitor",
                _compat.resolve_monitor(None), "sentinel monitor")
    finally:
        _compat.clear_script_context()
    t.equal("clearing it restores discovery",
            _compat.resolve_program(None), ctx.program)


def test_resolve_state(t, ctx):
    t.not_none("the script state is reachable", _compat.resolve_state())
    t.equal("an explicit state is returned unchanged",
            _compat.resolve_state("sentinel"), "sentinel")


def test_same_java_object(t, ctx):
    """`is` is not a safe identity test under JPype, which may wrap one Java
    object in a fresh proxy per call."""
    listing = ctx.program.getListing()
    t.check("two lookups of one Java object compare equal",
            _compat.same_java_object(ctx.program.getListing(), listing))
    t.check("a program is the same object as itself",
            _compat.same_java_object(ctx.program, ctx.program))
    t.check("different objects do not",
            not _compat.same_java_object(ctx.program, listing))
    t.check("None never matches an object",
            not _compat.same_java_object(None, ctx.program))
    t.check("None matches None", _compat.same_java_object(None, None))


def test_java_byte_array_round_trip(t, ctx):
    data = bytearray([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff])
    java_array = _compat.to_java_byte_array(data)
    t.equal("length survives", len(java_array), len(data))
    t.equal("values above 0x7f survive the signed round trip",
            _compat.from_java_byte_array(java_array), data)


def test_new_java_byte_array(t, ctx):
    buf = _compat.new_java_byte_array(8)
    t.equal("the requested length is allocated", len(buf), 8)
    t.equal("and it is readable as bytes",
            _compat.from_java_byte_array(buf), bytearray(8))


def test_java_class_of(t, ctx):
    from java.lang import String
    java_class = _compat.java_class_of(String)
    t.not_none("a java.lang.Class comes back", java_class)
    t.equal("and it describes the right type",
            str(java_class.getName()), "java.lang.String")
    t.equal("passing a Class through is idempotent",
            str(_compat.java_class_of(java_class).getName()),
            "java.lang.String")


def test_implementing_a_java_interface(t, ctx):
    """Jython subclasses the interface; JPype needs @JImplements/@JOverride."""
    from java.lang import Runnable

    calls = []

    @_compat.implements(Runnable)
    class Job(_compat.java_interface_base(Runnable)):
        @_compat.override
        def run(self):
            calls.append(True)

    job = Job()
    # hand it to Java as the interface, which is what actually exercises the
    # proxy -- calling job.run() directly would work even if it were not one
    from java.lang import Thread
    thread = Thread(job)
    thread.start()
    thread.join()
    t.equal("Java invoked the Python implementation through the interface",
            len(calls), 1)


def test_caught_errors_covers_java_exceptions(t, ctx):
    """A Java exception is not a Python Exception under Jython."""
    try:
        ctx.program.getMemory().getByte(
            ctx.program.getAddressFactory().getAddress("0xfffffff0"))
    except _compat.CAUGHT_ERRORS:
        t.check("a Java exception is caught by CAUGHT_ERRORS", True)
        return
    t.check("a Java exception is caught by CAUGHT_ERRORS", False,
            "no exception was raised at all")
