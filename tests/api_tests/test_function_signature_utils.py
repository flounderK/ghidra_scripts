#@runtime Jython
"""Tests for ghidra_api.function_signature_utils.

Mutating checks each use their own fixture function so they cannot disturb
the read-only checks or each other.
"""

from __main__ import *

from ghidra_api import function_signature_utils as fsu
from ghidra_api import datatype_utils as dtu
from ghidra_test_support import get_function, find_type


class Context(object):
    def __init__(self):
        self.program = currentProgram
        self.dtm = self.program.getDataTypeManager()
        self.takes_many = get_function(self.program, "takes_many")
        self.takes_nothing = get_function(self.program, "takes_nothing")
        self.takes_one_int = get_function(self.program, "takes_one_int")
        self.add_op = get_function(self.program, "add_op")
        self.inner = find_type(self.dtm, "Inner")


def setup_module():
    return Context()


def test_fixture_functions_present(t, ctx):
    for name in ("takes_many", "takes_nothing", "takes_one_int", "add_op"):
        t.not_none("fixture has %s" % name, getattr(ctx, name))


def test_get_datatype_for_param(t, ctx):
    first = fsu.getDataTypeForParam(ctx.takes_many, 1)
    t.not_none("the first parameter has a datatype", first)
    signature_args = list(ctx.takes_many.getSignature().getArguments())
    t.equal("param_num is 1-based, matching the decompiler",
            first, signature_args[0].getDataType())


def test_get_datatype_for_param_out_of_range(t, ctx):
    t.equal("a parameter beyond the signature returns None",
            fsu.getDataTypeForParam(ctx.takes_many, 99), None)
    t.equal("a function with no parameters returns None",
            fsu.getDataTypeForParam(ctx.takes_nothing, 1), None)


def test_get_datatype_for_param_rejects_zero(t, ctx):
    t.raises("param_num 0 is rejected", Exception,
             fsu.getDataTypeForParam, ctx.takes_many, 0)


def test_set_param_datatype(t, ctx):
    target = ctx.takes_one_int
    transaction = ctx.program.startTransaction("set param datatype")
    try:
        fsu.set_param_datatype(target, 1, ctx.dtm.getPointer(ctx.inner),
                               program=ctx.program)
        ctx.program.endTransaction(transaction, True)
    except Exception:
        ctx.program.endTransaction(transaction, False)
        raise
    applied = fsu.getDataTypeForParam(target, 1)
    t.not_none("the parameter still has a datatype", applied)
    if applied is not None:
        t.equal("the requested datatype was applied",
                applied.getName(), ctx.dtm.getPointer(ctx.inner).getName())


def test_set_num_params(t, ctx):
    target = ctx.takes_nothing
    transaction = ctx.program.startTransaction("set num params")
    try:
        fsu.set_num_params(target, 3, program=ctx.program)
        ctx.program.endTransaction(transaction, True)
    except Exception:
        ctx.program.endTransaction(transaction, False)
        raise
    t.equal("the function now reports the requested parameter count",
            len(list(target.getSignature().getArguments())), 3)
    t.equal("added parameters default to a pointer-sized undefined type",
            fsu.getDataTypeForParam(target, 3).getLength(),
            dtu.getUndefinedRegisterSizeDatatype(ctx.program).getLength())


def test_set_num_params_with_var_args(t, ctx):
    target = ctx.add_op
    transaction = ctx.program.startTransaction("set num params varargs")
    try:
        fsu.set_num_params(target, 2, var_args=True, program=ctx.program)
        ctx.program.endTransaction(transaction, True)
    except Exception:
        ctx.program.endTransaction(transaction, False)
        raise
    t.check("the function is marked variadic", target.hasVarArgs())
