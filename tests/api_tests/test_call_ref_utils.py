#@runtime Jython
"""Tests for ghidra_api.call_ref_utils against the api_test_cases fixture.

The fixture provides a deliberate call chain -- top_caller -> middle_caller
-> leaf -- plus a self-recursive countdown() and an indirect call.
"""

from __main__ import *

from ghidra_api import call_ref_utils as cru
from ghidra_test_support import get_function


class Context(object):
    def __init__(self):
        self.program = currentProgram
        self.leaf = get_function(self.program, "leaf")
        self.middle = get_function(self.program, "middle_caller")
        self.top = get_function(self.program, "top_caller")
        self.countdown = get_function(self.program, "countdown")
        self.add_op = get_function(self.program, "add_op")


def setup_module():
    return Context()


def test_fixture_functions_present(t, ctx):
    for name in ("leaf", "middle", "top", "countdown"):
        t.not_none("fixture has %s" % name, getattr(ctx, name))


def test_calling_addresses_to_address(t, ctx):
    callers = cru.get_calling_addresses_to_address(ctx.leaf.getEntryPoint(),
                                                   program=ctx.program)
    t.check("leaf has at least one caller", len(callers) > 0)
    t.check("every caller address lies inside middle_caller",
            all(ctx.middle.getBody().contains(a) for a in callers),
            "addresses=%s" % [str(a) for a in callers])


def test_calling_addresses_defaults_to_current_program(t, ctx):
    t.equal("omitting program uses currentProgram",
            [str(a) for a in cru.get_calling_addresses_to_address(ctx.leaf.getEntryPoint())],
            [str(a) for a in cru.get_calling_addresses_to_address(
                ctx.leaf.getEntryPoint(), program=ctx.program)])


def test_called_addresses_from_address(t, ctx):
    # every call site inside middle_caller should resolve to leaf
    targets = []
    for address_range in ctx.middle.getBody().getAddressRanges():
        address = address_range.getMinAddress()
        while address is not None and address_range.contains(address):
            targets.extend(cru.get_called_addresses_from_address(address,
                                                                 program=ctx.program))
            address = address.next()
    t.check("middle_caller makes at least one call", len(targets) > 0)
    t.contains("middle_caller calls leaf",
               [str(a) for a in targets], str(ctx.leaf.getEntryPoint()))


def test_callsites_for_func_by_name(t, ctx):
    callsites = cru.get_callsites_for_func_by_name("leaf", program=ctx.program)
    t.contains("leaf's callsites are attributed to middle_caller",
               [f.getName() for f in callsites], "middle_caller")
    for func, addresses in callsites.items():
        t.check("callsite addresses lie inside the calling function (%s)" % func.getName(),
                all(func.getBody().contains(a) for a in addresses))


def test_callsites_for_unknown_name_is_empty(t, ctx):
    t.equal("an unknown function name yields no callsites",
            cru.get_callsites_for_func_by_name("no_such_function_xyz",
                                               program=ctx.program), {})


def test_function_calls_self(t, ctx):
    t.check("countdown is detected as self-recursive",
            cru.function_calls_self(ctx.countdown, program=ctx.program))
    t.check("leaf is not self-recursive",
            not cru.function_calls_self(ctx.leaf, program=ctx.program))


def test_all_functions_leading_to(t, ctx):
    callers = cru.get_all_functions_leading_to(ctx.leaf, program=ctx.program)
    names = set(f.getName() for f in callers if f is not None)
    t.contains("direct caller is included", names, "middle_caller")
    t.contains("transitive caller is included", names, "top_caller")
    t.check("leaf itself is excluded when it is not self-recursive",
            "leaf" not in names, "names=%s" % sorted(names))


def test_all_functions_leading_to_none_is_empty(t, ctx):
    t.equal("None yields an empty set",
            cru.get_all_functions_leading_to(None, program=ctx.program), set())


def test_all_functions_leading_to_keeps_self_recursive(t, ctx):
    callers = cru.get_all_functions_leading_to(ctx.countdown, program=ctx.program)
    names = set(f.getName() for f in callers if f is not None)
    t.contains("a self-recursive function keeps itself in the result",
               names, "countdown")


def test_all_functions_called_from(t, ctx):
    called = cru.get_all_functions_called_from(ctx.top, program=ctx.program)
    names = set(f.getName() for f in called if f is not None)
    t.contains("direct callee is included", names, "middle_caller")
    t.contains("transitive callee is included", names, "leaf")


def test_all_functions_called_from_none_is_empty(t, ctx):
    t.equal("None yields an empty set",
            cru.get_all_functions_called_from(None, program=ctx.program), set())
