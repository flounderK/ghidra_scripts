"""
Shims that let this package run under both Jython (Ghidra's bundled
interpreter, and the Jython extension on newer releases) and CPython
(PyGhidra).

The two runtimes differ in one way that matters to every module here: where
the FlatProgramAPI lives.

Under Jython the running script *is* the ``__main__`` module, so a module that
says ``from __main__ import *`` picks up ``currentProgram`` and every flat API
method for free. That is the trick the rest of this repo is built on.

Under PyGhidra it does not hold. PyGhidra execs the script with a globals
mapping that proxies a live ``GhidraScript`` -- bare names resolve inside the
script itself, but the mapping is never registered as ``sys.modules['__main__']``,
which still holds the launcher's namespace. An imported module therefore sees
none of it, and every bare ``currentProgram`` or ``getFunctionContaining`` is a
NameError.

:func:`flat_api` papers over that. It returns something with the flat API on
it, whichever runtime is in play, and the helpers below go through it. Scripts
can keep using bare names -- those work on both runtimes, because in a script
PyGhidra's proxy resolves them -- but *modules* must call through here.
"""

import sys

try:
    # In Jython a Java exception is not a Python Exception, so a plain
    # `except Exception` silently fails to catch anything Ghidra throws.
    # Under CPython/PyGhidra the import fails and Java errors arrive as
    # ordinary Python exceptions.
    from java.lang import Exception as JavaException
    CAUGHT_ERRORS = (Exception, JavaException)
except:  # noqa: E722 - must not itself use `except Exception`
    CAUGHT_ERRORS = (Exception,)


# Set by set_script_context() to override discovery entirely.
_SCRIPT_CONTEXT = None


def set_script_context(context):
    """Pin the object the flat API is read from.

    Needed where neither discovery route applies: an embedded interpreter, a
    test harness, or the ``pyghidra`` CLI, which execs its script in a
    namespace that carries no ``__this__``. Pass a GhidraScript, a
    FlatProgramAPI, or any object exposing the same names.
    """
    global _SCRIPT_CONTEXT
    _SCRIPT_CONTEXT = context


def clear_script_context():
    set_script_context(None)


def _pyghidra_script():
    """The GhidraScript of the running PyGhidra script, by walking the stack.

    PyGhidra puts ``__this__`` -- the GhidraScript itself -- in the globals it
    execs a script with. Any call into this package happens underneath that
    script's frame, so walking out to it recovers the API that the script can
    see and an imported module cannot. Returns None under Jython, where no
    frame carries ``__this__``.
    """
    try:
        frame = sys._getframe(1)
    except (AttributeError, ValueError):
        return None
    while frame is not None:
        context = frame.f_globals.get("__this__")
        if context is not None:
            return context
        frame = frame.f_back
    return None


def flat_api():
    """An object exposing Ghidra's FlatProgramAPI, whichever runtime this is.

    Raises RuntimeError when there is no script context at all, which means
    the caller is outside Ghidra and should pass program= explicitly.
    """
    if _SCRIPT_CONTEXT is not None:
        return _SCRIPT_CONTEXT

    # PyGhidra first: it reflects the script actually running, where a stale
    # __main__ attribute might not.
    context = _pyghidra_script()
    if context is not None:
        return context

    try:
        import __main__
    except ImportError:
        __main__ = None
    if __main__ is not None and hasattr(__main__, "currentProgram"):
        return __main__

    raise RuntimeError(
        "No Ghidra script context found. Run this inside Ghidra, pass "
        "program= explicitly, or call _compat.set_script_context().")


def _from_script(name, default=None):
    try:
        context = flat_api()
    except RuntimeError:
        return default
    return getattr(context, name, default)


def resolve_program(program):
    if program is not None:
        return program
    result = _from_script("currentProgram")
    if result is None:
        raise RuntimeError(
            "currentProgram is None. is a program open in Ghidra?")
    return result


def resolve_monitor(monitor):
    if monitor is not None:
        return monitor
    result = _from_script("monitor")
    if result is not None:
        return result
    from ghidra.util.task import ConsoleTaskMonitor
    return ConsoleTaskMonitor()


def resolve_state(state=None):
    """The GhidraScript state, for scripts that set selections or navigate."""
    if state is not None:
        return state
    result = _from_script("state")
    if result is None:
        raise RuntimeError(
            "No script state available; this needs to run as a Ghidra script.")
    return result


# --- flat API calls, routed through the program rather than ambient names ---
# Each of these exists because a module cannot call the bare flat API method
# under PyGhidra. Where the Program offers the same thing directly, that is
# used in preference to going back through the script.

def get_function_containing(program, addr):
    return program.getFunctionManager().getFunctionContaining(addr)


def get_function_at(program, addr):
    return program.getFunctionManager().getFunctionAt(addr)


def get_memory_blocks(program):
    return list(program.getMemory().getBlocks())


def get_data_at(program, addr):
    return program.getListing().getDataAt(addr)


def get_instruction_at(program, addr):
    return program.getListing().getInstructionAt(addr)


def get_references_to(program, addr):
    return program.getReferenceManager().getReferencesTo(addr)


def get_references_from(program, addr):
    return program.getReferenceManager().getReferencesFrom(addr)


def to_addr(program, offset):
    if isinstance(offset, str):
        return program.getAddressFactory().getAddress(offset)
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    return addr_space.getAddress(offset)


def get_bytes(program, addr, size):
    """Read @size bytes at @addr, returning a Java byte[]."""
    buf = new_java_byte_array(size)
    program.getMemory().getBytes(addr, buf)
    return buf


def run_command(program, cmd):
    tx_id = program.startTransaction(cmd.getName())
    try:
        success = cmd.applyTo(program)
        program.endTransaction(tx_id, success)
        return success
    except CAUGHT_ERRORS:
        # Ghidra commands throw Java exceptions; `except Exception` would not
        # catch them under Jython and the transaction would be left open
        program.endTransaction(tx_id, False)
        raise


# --- Java array interop -----------------------------------------------------

def same_java_object(first, second):
    """Whether two references point at the same Java object.

    Jython hands back one stable Python proxy per Java object, so `is` answers
    this correctly there. JPype may build a fresh proxy on every call, so `is`
    can be False for what is one Java object -- which silently turns an
    identity guard into "always different". `==` reaches Java's equals(), which
    for the identity-compared types this is used on (Program, and friends) is
    exactly the question being asked.
    """
    if first is second:
        return True
    if first is None or second is None:
        return False
    return bool(first == second)


def new_java_byte_array(size):
    """An uninitialised Java byte[] of @size."""
    try:
        import jarray
        return jarray.zeros(size, 'b')
    except ImportError:
        import jpype
        # JArray(JByte) is the array *class*; calling it with a length
        # allocates. jpype.JByte(size) would be a scalar cast, which is the
        # easy mistake to make here.
        return jpype.JArray(jpype.JByte)(int(size))


def to_java_byte_array(data):
    """Copy a Python bytes/bytearray into a Java byte[].

    Java bytes are signed, so anything above 0x7f has to be biased into the
    negative half before the array is built or both runtimes reject it.
    """
    signed = [(b - 256) if b > 127 else b for b in bytearray(data)]
    try:
        import jarray
        return jarray.array(signed, 'b')
    except ImportError:
        import jpype
        return jpype.JArray(jpype.JByte)(signed)


def from_java_byte_array(data):
    """Copy a Java byte[] into a Python bytearray, undoing the sign bias."""
    return bytearray((b & 0xff) for b in data)


# --- Java class and interface interop ---------------------------------------

def java_class_of(jclass):
    """The java.lang.Class for a Java type, for reflection.

    Jython hands the reflection methods straight off the type object; JPype
    keeps java.lang.Class behind ``class_``.
    """
    inner = getattr(jclass, "class_", None)
    return inner if inner is not None else jclass


def implements(*interfaces):
    """Class decorator for implementing a Java interface on either runtime.

    Jython implements a Java interface by plain subclassing. JPype refuses
    that -- "Java classes cannot be extended in Python" -- and wants
    @JImplements instead, so under PyGhidra the class is declared against
    `object` and this decorator attaches the interface.
    """
    try:
        import jpype
    except ImportError:
        # Jython: the class already subclasses the interface, nothing to do.
        return lambda cls: cls

    names = [i.class_.getName() if hasattr(i, "class_") else i
             for i in interfaces]

    def decorate(cls):
        return jpype.JImplements(*names)(cls)
    return decorate


def override(func):
    """Mark a method as implementing a Java interface method.

    JPype needs @JOverride to match a Python method up to the interface method
    it implements. Jython needs nothing, so this is the identity there.
    """
    try:
        import jpype
    except ImportError:
        return func
    return jpype.JOverride(func)


def java_interface_base(*interfaces):
    """The base class to declare a Java-interface implementation against.

    Under Jython that is the interface itself; under JPype it must be object,
    with :func:`implements` attaching the interface afterwards.
    """
    try:
        import jpype  # noqa: F401
    except ImportError:
        return interfaces[0] if len(interfaces) == 1 else interfaces
    return object
