#@runtime Jython
"""Tests for ghidra_api.register_utils."""

from __main__ import *

from ghidra_api import register_utils as ru
from ghidra_test_support import get_function


class Context(object):
    def __init__(self):
        self.program = currentProgram
        self.main = get_function(self.program, "main")
        self.takes_many = get_function(self.program, "takes_many")


def setup_module():
    return Context()


def test_stack_register(t, ctx):
    register = ru.getStackRegister(program=ctx.program)
    t.not_none("a stack register is reported", register)
    if register is None:
        return
    t.equal("stack register matches the compiler spec",
            register, ctx.program.getCompilerSpec().getStackPointer())


def test_stack_register_defaults_to_current_program(t, ctx):
    t.equal("omitting program uses currentProgram",
            ru.getStackRegister(), ru.getStackRegister(program=ctx.program))


def test_all_contained_registers_includes_itself(t, ctx):
    stack = ru.getStackRegister(program=ctx.program)
    contained = ru.getAllContainedRegisters(stack)
    t.contains("the register itself is included", contained, stack)


def test_all_contained_registers_includes_children(t, ctx):
    stack = ru.getStackRegister(program=ctx.program)
    contained = ru.getAllContainedRegisters(stack)
    children = [c for c in stack.getChildRegisters() if c is not None]
    for child in children:
        t.contains("child register %s is included" % child.getName(),
                   contained, child)
    t.check("traversal terminates and returns a set",
            isinstance(contained, set) and len(contained) >= 1,
            "found %d" % len(contained))


def test_gpr_to_param_map(t, ctx):
    mapping = ru.getGeneralPurposeRegsToParamMapForCallingConvention(
        None, program=ctx.program)
    t.check("a register to parameter map is produced", len(mapping) > 0,
            "size=%d" % len(mapping))
    t.check("parameter numbers start at 1",
            min(mapping.values()) == 1,
            "min=%s" % (min(mapping.values()) if mapping else None))
    t.check("parameter numbers are contiguous",
            sorted(set(mapping.values())) == list(range(1, max(mapping.values()) + 1)),
            "values=%s" % sorted(set(mapping.values())))
    t.check("no vector registers are included",
            not any(r.getBaseRegister().isVectorRegister() for r in mapping),
            "vector registers leaked into the map")


def test_reg_to_param_map_for_func(t, ctx):
    mapping = ru.getRegToParamMapForFunc(ctx.takes_many)
    t.check("a map is produced for a function", len(mapping) > 0)
    again = ru.getRegToParamMapForFunc(ctx.takes_many)
    t.check("repeat lookups are served from the cache", mapping is again)
    t.contains("the calling convention was cached",
               ru.GPR_TO_PARAM_MAP_CACHE.values(), mapping)
