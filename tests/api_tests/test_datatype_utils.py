#@runtime Jython
"""Tests for ghidra_api.datatype_utils against the api_test_cases fixture."""

from __main__ import *
from ghidra.program.model.data import Pointer, PointerDataType

from ghidra_api import datatype_utils as dtu
from ghidra_api._compat import CAUGHT_ERRORS
from ghidra_test_support import find_type, global_data


class Context(object):
    def __init__(self):
        self.program = currentProgram
        self.dtm = currentProgram.getDataTypeManager()
        self.listing = currentProgram.getListing()
        self.inner = find_type(self.dtm, "Inner")
        self.middle = find_type(self.dtm, "Middle")
        self.outer = find_type(self.dtm, "Outer")
        self.int_type = find_type(self.dtm, "int")


def setup_module():
    return Context()


def test_fixture_types_were_recovered(t, ctx):
    # if this fails the rest are meaningless -- the fixture lost its debug info
    t.not_none("Inner type recovered from DWARF", ctx.inner)
    t.not_none("Middle type recovered from DWARF", ctx.middle)
    t.not_none("Outer type recovered from DWARF", ctx.outer)


def test_undefined_register_size_datatype(t, ctx):
    datatype = dtu.getUndefinedRegisterSizeDatatype(program=ctx.program)
    t.not_none("undefined pointer-size datatype exists", datatype)
    if datatype is None:
        return
    t.equal("undefined datatype is pointer sized",
            datatype.getLength(), ctx.program.getDefaultPointerSize())
    t.equal("undefined datatype is named for its size",
            datatype.getName(), "undefined%d" % ctx.program.getDefaultPointerSize())


def test_undefined_register_size_defaults_to_current_program(t, ctx):
    t.equal("omitting program uses currentProgram",
            dtu.getUndefinedRegisterSizeDatatype(),
            dtu.getUndefinedRegisterSizeDatatype(program=ctx.program))


def test_generic_pointer_datatype(t, ctx):
    datatype = dtu.getGenericPointerDatatype()
    t.not_none("generic pointer datatype exists", datatype)
    t.check("generic pointer is a PointerDataType",
            isinstance(datatype, PointerDataType))


def test_void_pointer_datatype(t, ctx):
    datatype = dtu.getVoidPointerDatatype(program=ctx.program)
    t.not_none("void pointer datatype exists", datatype)
    if datatype is None:
        return
    t.check("void pointer is a Pointer", isinstance(datatype, Pointer))
    t.equal("void pointer is pointer sized",
            datatype.getLength(), ctx.program.getDefaultPointerSize())
    t.equal("void pointer points at void", datatype.getDataType().getName(), "void")


def test_equally_unique_same_type(t, ctx):
    t.check("a struct is equally unique to itself",
            dtu.areBaseDataTypesEquallyUnique(ctx.inner, ctx.inner))


def test_equally_unique_unwraps_pointers(t, ctx):
    # getBaseDataType unwraps pointers, so Inner* and Inner compare equal
    inner_pointer = ctx.dtm.getPointer(ctx.inner)
    t.check("a pointer compares equal to its base type",
            dtu.areBaseDataTypesEquallyUnique(inner_pointer, ctx.inner))


def test_equally_unique_distinguishes_kinds(t, ctx):
    t.check("a struct is not equally unique to an int",
            not dtu.areBaseDataTypesEquallyUnique(ctx.inner, ctx.int_type))


def test_find_datatypes_using_includes_self_and_users(t, ctx):
    users = dtu.find_datatypes_using(ctx.inner)
    t.contains("result includes the datatype itself", users, ctx.inner)
    t.contains("result includes a struct holding it by value", users, ctx.middle)
    names = sorted(set(d.getName() for d in users))
    t.check("result includes a pointer to it",
            any(n.startswith("Inner *") or n == "Inner *" for n in names),
            "names=%s" % names[:12])


def test_find_datatypes_using_full_chains_is_a_superset(t, ctx):
    full = dtu.find_datatypes_using(ctx.inner, check_full_chains=True)
    direct = dtu.find_datatypes_using(ctx.inner, check_full_chains=False)
    t.check("check_full_chains=False yields no more than the full walk",
            len(direct) <= len(full), "direct=%d full=%d" % (len(direct), len(full)))
    t.check("both walks include the datatype itself",
            ctx.inner in full and ctx.inner in direct)


def test_get_all_sub_components_of_datadb(t, ctx):
    data = global_data(ctx.program, "g_outer")
    t.not_none("g_outer has defined data in the listing", data)
    if data is None:
        return
    components = dtu.get_all_sub_components_of_datadb(data)
    t.check("walking g_outer yields its nested components",
            len(components) > 1, "found %d" % len(components))
    type_names = set()
    for component in components:
        component_type = getattr(component, "dataType", None)
        if component_type is not None:
            type_names.add(component_type.getName())
    t.contains("nested Inner component is reached", type_names, "Inner")


def test_get_all_defined_datatype_instances(t, ctx):
    instances = dtu.get_all_defined_datatype_instances(ctx.inner)
    t.check("finds defined instances of Inner", len(instances) > 0,
            "found %d" % len(instances))
    t.check("every instance really is an Inner",
            all(i.dataType == ctx.inner for i in instances))


def test_apply_datatype_at_address(t, ctx):
    # g_scratch exists so this destructive check disturbs nothing else
    symbols = list(ctx.program.getSymbolTable().getGlobalSymbols("g_scratch"))
    t.check("fixture provides a scratch global", len(symbols) > 0)
    if not symbols:
        return
    address = symbols[0].getAddress()
    transaction = ctx.program.startTransaction("apply datatype")
    try:
        dtu.applyDataTypeAtAddress(address, ctx.inner, program=ctx.program)
        ctx.program.endTransaction(transaction, True)
    except CAUGHT_ERRORS:
        ctx.program.endTransaction(transaction, False)
        raise
    applied = ctx.listing.getDataAt(address)
    t.not_none("data was created at the scratch address", applied)
    if applied is not None:
        t.equal("applied datatype is the one requested",
                applied.getDataType().getName(), ctx.inner.getName())
