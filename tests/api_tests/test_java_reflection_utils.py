#@runtime Jython
"""Tests for ghidra_api.java_reflection_utils, using core Java classes."""

from __main__ import *
from java.lang import String, Integer, Object

from ghidra_api import java_reflection_utils as jru


def declared_method(javaclass, name, param_types):
    """The overload of @name whose parameter types are exactly @param_types."""
    for method in javaclass.getDeclaredMethods():
        if method.getName() != name:
            continue
        if list(method.getParameterTypes()) == list(param_types):
            return method
    return None


class Context(object):
    def __init__(self):
        self.index_of_int = declared_method(String, "indexOf", [Integer.TYPE])
        self.index_of_string = declared_method(String, "indexOf", [String])


def setup_module():
    return Context()


def test_fixture_methods_found(t, ctx):
    t.not_none("String.indexOf(int) located", ctx.index_of_int)
    t.not_none("String.indexOf(String) located", ctx.index_of_string)


def test_get_java_field(t, ctx):
    field = jru.get_java_field(String, "hash")
    t.not_none("a private field is found", field)
    t.equal("the field has the requested name",
            field.getName() if field else None, "hash")


def test_get_accessible_java_field(t, ctx):
    # java.base does not open java.lang to unnamed modules, so use a Ghidra
    # class -- which is what this helper actually exists to reach into
    program_class = currentProgram.getClass()
    fields = jru.get_all_declared_fields(program_class)
    t.check("the program class has declared fields", len(fields) > 0)
    if not fields:
        return
    name = fields[0].getName()
    field = jru.get_accessible_java_field(program_class, name)
    t.not_none("an accessible field is returned", field)
    if field is not None:
        t.check("the field was made accessible", field.isAccessible())


def test_get_all_declared_fields(t, ctx):
    fields = jru.get_all_declared_fields(String)
    t.check("declared fields are returned", len(fields) > 0)
    names = [f.getName() for f in fields]
    t.contains("a known field is present", names, "hash")


def test_get_all_declared_methods(t, ctx):
    methods = jru.get_all_declared_methods(String)
    names = set(m.getName() for m in methods)
    t.contains("a known method is present", names, "indexOf")


def test_get_all_declared_fields_can_include_object(t, ctx):
    without = jru.get_all_declared_fields(String, ignore_object_fields=True)
    with_object = jru.get_all_declared_fields(String, ignore_object_fields=False)
    t.check("including Object's members yields at least as many",
            len(with_object) >= len(without),
            "with=%d without=%d" % (len(with_object), len(without)))


def test_satisfies_no_constraints(t, ctx):
    t.check("a method with no constraints is always satisfied",
            jru.satisfies_parameter_constraints(ctx.index_of_int, {}))


def test_satisfies_rejects_out_of_range_constraint(t, ctx):
    t.check("a constraint beyond the parameter count is rejected",
            not jru.satisfies_parameter_constraints(ctx.index_of_int, {5: String}))


def test_satisfies_matching_parameter_type(t, ctx):
    t.check("indexOf(String) satisfies a String constraint on param 0",
            jru.satisfies_parameter_constraints(ctx.index_of_string, {0: String}))


def test_satisfies_rejects_mismatched_parameter_type(t, ctx):
    t.check("indexOf(int) does not satisfy a String constraint on param 0",
            not jru.satisfies_parameter_constraints(ctx.index_of_int, {0: String}))


def test_get_method_by_param_constraints_selects_overload(t, ctx):
    method = jru.get_java_method_by_param_constraints(String, "indexOf", {0: String})
    t.not_none("an overload is selected", method)
    if method is None:
        return
    t.equal("the selected overload takes a String first",
            list(method.getParameterTypes())[0], String)


def test_get_constructor_by_param_constraints(t, ctx):
    ctor = jru.get_java_constructor_by_param_constraints(String, {})
    t.not_none("a constructor is found with no constraints", ctor)
