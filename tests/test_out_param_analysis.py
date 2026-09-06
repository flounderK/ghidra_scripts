#!/usr/bin/env python3
"""Unit tests for out_param_analysis.py.

The Ghidra API is stubbed, so this runs under plain CPython 3 -- no Ghidra:
    python3 tests/test_out_param_analysis.py
"""

import os
import sys
import types
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

STACK_REG_OFFSET = 0x100
CALLSITES = {}          # func_name -> {FakeFunction: [addr, ..]}
PCODE = {}              # FakeFunction -> [FakePcodeOp] or None
DECOMPILED = {}         # FakeFunction.name -> times decompiled
CALLSITE_LOOKUPS = {}   # func_name -> times looked up


class FakeVarnode(object):
    def __init__(self, const=False, addr=False, reg=False, off=0, back_slice=None):
        self._const, self._addr, self._reg, self._off = const, addr, reg, off
        self.back_slice = back_slice if back_slice is not None else []

    def isConstant(self):
        return self._const

    def isAddress(self):
        return self._addr

    def isRegister(self):
        return self._reg

    def getOffset(self):
        return self._off


def stack_varnode():
    """A varnode whose backward slice reaches the stack pointer."""
    return FakeVarnode(back_slice=[FakeVarnode(reg=True, off=STACK_REG_OFFSET)])


def heap_varnode():
    """A varnode whose backward slice never touches the stack pointer."""
    return FakeVarnode(back_slice=[FakeVarnode(reg=True, off=0x8)])


class FakeSeqNum(object):
    def __init__(self, target):
        self.target = target


class FakePcodeOp(object):
    def __init__(self, opcode, target, inputs):
        self.opcode, self.seqnum, self._inputs = opcode, FakeSeqNum(target), inputs

    def getInput(self, index):
        return self._inputs[index] if index < len(self._inputs) else None


class FakeFunction(object):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "FakeFunction(%s)" % self.name


class FakeProgram(object):
    def __init__(self, name="prog"):
        self.name = name


def _install_ghidra_stubs():
    def module(name):
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        return mod

    for name in ("ghidra", "ghidra.program", "ghidra.program.model",
                 "ghidra.app", "ghidra.app.decompiler"):
        module(name)

    pcode = module("ghidra.program.model.pcode")

    class PcodeOpAST(object):
        CALL = "CALL"

    pcode.PcodeOpAST = PcodeOpAST

    component = module("ghidra.app.decompiler.component")

    class DecompilerUtils(object):
        @staticmethod
        def getBackwardSlice(varnode):
            return varnode.back_slice

    component.DecompilerUtils = DecompilerUtils

    api = module("ghidra_api")
    call_ref_utils = module("ghidra_api.call_ref_utils")
    decomp_utils = module("ghidra_api.decomp_utils")
    register_utils = module("ghidra_api.register_utils")
    api.call_ref_utils = call_ref_utils
    api.decomp_utils = decomp_utils
    api.register_utils = register_utils

    class StackRegister(object):
        def getOffset(self):
            return STACK_REG_OFFSET

    register_utils.getStackRegister = lambda program=None: StackRegister()

    class DecompUtils(object):
        def __init__(self, program=None, **kwargs):
            self.program = program

        def get_pcode_for_function(self, func, **kwargs):
            DECOMPILED[func.name] = DECOMPILED.get(func.name, 0) + 1
            return PCODE.get(func)

    decomp_utils.DecompUtils = DecompUtils

    def get_callsites_for_func_by_name(func_name, program=None):
        CALLSITE_LOOKUPS[func_name] = CALLSITE_LOOKUPS.get(func_name, 0) + 1
        return CALLSITES.get(func_name, {})

    call_ref_utils.get_callsites_for_func_by_name = get_callsites_for_func_by_name


_install_ghidra_stubs()
currentProgram = FakeProgram("current")  # picked up by `from __main__ import *`

import out_param_analysis as opa  # noqa: E402


def reset():
    CALLSITES.clear()
    PCODE.clear()
    DECOMPILED.clear()
    CALLSITE_LOOKUPS.clear()


def desc(**kwargs):
    kwargs.setdefault("func_name", "memcpy")
    return opa.FuncOutParamAnalysisDesc(**kwargs)


def call_op(addr=0x1000, args=None):
    """A CALL op; input 0 is the call target, so args start at input 1."""
    inputs = [FakeVarnode(addr=True)] + list(args or [])
    return FakePcodeOp("CALL", addr, inputs)


class TestCallParamAttributes(unittest.TestCase):
    def setUp(self):
        reset()

    def attrs(self, d, op):
        return opa.get_call_param_attributes(op, d, STACK_REG_OFFSET)

    def test_absent_src_size_counts_as_variable(self):
        # strcpy-like: no size parameter at all means the size is inferred
        a = self.attrs(desc(out_param_no=1, src_param_no=2), call_op(args=[heap_varnode()]))
        self.assertTrue(a.var_src_size)

    def test_absent_src_param_counts_as_variable(self):
        a = self.attrs(desc(out_param_no=1), call_op(args=[heap_varnode()]))
        self.assertTrue(a.var_src)

    def test_constant_src_size_is_not_variable(self):
        d = desc(out_param_no=1, src_param_no=2, src_size_param_no=3)
        op = call_op(args=[heap_varnode(), heap_varnode(), FakeVarnode(const=True)])
        self.assertFalse(self.attrs(d, op).var_src_size)

    def test_non_constant_src_size_is_variable(self):
        d = desc(out_param_no=1, src_param_no=2, src_size_param_no=3)
        op = call_op(args=[heap_varnode(), heap_varnode(), FakeVarnode(reg=True)])
        self.assertTrue(self.attrs(d, op).var_src_size)

    def test_non_constant_dest_size_is_variable(self):
        d = desc(out_param_no=1, dest_size_param_no=2)
        op = call_op(args=[heap_varnode(), FakeVarnode(reg=True)])
        self.assertTrue(self.attrs(d, op).var_dest_size)

    def test_stack_dest_detected_through_backward_slice(self):
        a = self.attrs(desc(out_param_no=1), call_op(args=[stack_varnode()]))
        self.assertTrue(a.stack_dest)
        self.assertTrue(a.var_dest)

    def test_non_stack_dest_not_flagged(self):
        self.assertFalse(self.attrs(desc(out_param_no=1),
                                    call_op(args=[heap_varnode()])).stack_dest)

    def test_stack_src_detected(self):
        d = desc(out_param_no=1, src_param_no=2)
        a = self.attrs(d, call_op(args=[heap_varnode(), stack_varnode()]))
        self.assertTrue(a.stack_src)

    def test_constant_dest_is_const_or_addr(self):
        a = self.attrs(desc(out_param_no=1), call_op(args=[FakeVarnode(const=True)]))
        self.assertTrue(a.const_or_addr_dest)
        self.assertFalse(a.var_dest)

    def test_address_dest_is_const_or_addr(self):
        a = self.attrs(desc(out_param_no=1), call_op(args=[FakeVarnode(addr=True)]))
        self.assertTrue(a.const_or_addr_dest)

    def test_missing_argument_is_tolerated(self):
        # callee signature narrower than the desc expects
        a = self.attrs(desc(out_param_no=1, src_param_no=9), call_op(args=[stack_varnode()]))
        self.assertTrue(a.stack_dest)


class TestRecordCall(unittest.TestCase):
    def setUp(self):
        reset()

    def bucket(self, d, **flags):
        a = opa.CallParamAttributes(d)
        for key, value in flags.items():
            setattr(a, key, value)
        func = FakeFunction("caller")
        opa.record_call(d, func, 0x2000, a)
        return {name: dict(getattr(d, name))
                for name in ("stack_dest_var_dest_size_by_func",
                             "stack_dest_var_or_no_src_size_by_func",
                             "stack_src_var_or_no_src_size_by_func",
                             "all_params_var_by_func",
                             "const_dest_var_or_no_src_size_by_func")
                if getattr(d, name)}

    def test_stack_dest_with_variable_dest_size(self):
        d = desc(out_param_no=1, src_size_param_no=4, dest_size_param_no=2)
        got = self.bucket(d, stack_dest=True, var_dest_size=True, var_src_size=False)
        self.assertEqual(list(got), ["stack_dest_var_dest_size_by_func"])

    def test_stack_dest_with_variable_src_size(self):
        d = desc(out_param_no=1, src_param_no=2)
        got = self.bucket(d, stack_dest=True, var_src_size=True, var_dest=False)
        self.assertIn("stack_dest_var_or_no_src_size_by_func", got)

    def test_stack_src_info_leak(self):
        d = desc(out_param_no=1, src_param_no=2)
        got = self.bucket(d, stack_src=True, var_src_size=True)
        self.assertIn("stack_src_var_or_no_src_size_by_func", got)

    def test_all_params_variable(self):
        d = desc(out_param_no=1, src_param_no=2, src_size_param_no=3)
        got = self.bucket(d, var_dest=True, var_src=True, var_src_size=True)
        self.assertIn("all_params_var_by_func", got)

    def test_all_params_variable_requires_variable_dest_size_when_present(self):
        d = desc(out_param_no=1, src_param_no=3, src_size_param_no=4, dest_size_param_no=2)
        got = self.bucket(d, var_dest=True, var_src=True, var_src_size=True,
                          var_dest_size=False)
        self.assertNotIn("all_params_var_by_func", got)

    def test_const_dest_possible_global_overflow(self):
        d = desc(out_param_no=1, src_param_no=2)
        got = self.bucket(d, const_or_addr_dest=True, var_src_size=True)
        self.assertIn("const_dest_var_or_no_src_size_by_func", got)

    def test_nothing_recorded_when_no_flags_match(self):
        d = desc(out_param_no=1, src_param_no=2, src_size_param_no=3)
        self.assertEqual(self.bucket(d), {})


class TestOutParamAnalysis(unittest.TestCase):
    def setUp(self):
        reset()

    def test_each_caller_decompiled_once_across_descs(self):
        caller = FakeFunction("caller")
        ops = [call_op(0x1000, [stack_varnode()]), call_op(0x1004, [stack_varnode()])]
        PCODE[caller] = ops
        CALLSITES["memcpy"] = {caller: [0x1000]}
        CALLSITES["strcpy"] = {caller: [0x1004]}
        col = opa.OutParamAnalysisCollection([
            desc(func_name="memcpy", out_param_no=1, src_size_param_no=3, src_param_no=2),
            desc(func_name="strcpy", out_param_no=1, src_param_no=2),
        ])
        opa.out_param_analysis(col, program=FakeProgram())
        self.assertEqual(DECOMPILED, {"caller": 1})

    def test_undecompilable_function_is_skipped_not_fatal(self):
        good, bad = FakeFunction("good"), FakeFunction("bad")
        PCODE[good] = [call_op(0x1000, [stack_varnode()])]
        PCODE[bad] = None
        CALLSITES["strcpy"] = {good: [0x1000], bad: [0x2000]}
        d = desc(func_name="strcpy", out_param_no=1, src_param_no=2)
        opa.out_param_analysis(opa.OutParamAnalysisCollection([d]), program=FakeProgram())
        self.assertEqual(dict(d.stack_dest_var_or_no_src_size_by_func), {good: {0x1000}})

    def test_callsite_without_matching_call_op_is_ignored(self):
        caller = FakeFunction("caller")
        PCODE[caller] = [FakePcodeOp("COPY", 0x1000, [])]
        CALLSITES["strcpy"] = {caller: [0x1000]}
        d = desc(func_name="strcpy", out_param_no=1, src_param_no=2)
        opa.out_param_analysis(opa.OutParamAnalysisCollection([d]), program=FakeProgram())
        self.assertEqual(dict(d.stack_dest_var_or_no_src_size_by_func), {})

    def test_findings_recorded_at_call_address(self):
        caller = FakeFunction("caller")
        PCODE[caller] = [call_op(0x1234, [stack_varnode()])]
        CALLSITES["strcpy"] = {caller: [0x1234]}
        d = desc(func_name="strcpy", out_param_no=1, src_param_no=2)
        opa.out_param_analysis(opa.OutParamAnalysisCollection([d]), program=FakeProgram())
        self.assertEqual(d.stack_dest_var_or_no_src_size_by_func[caller], {0x1234})

    def test_single_out_param_analysis_returns_populated_desc(self):
        # regression: this raised NameError('desc') before the refactor
        caller = FakeFunction("caller")
        PCODE[caller] = [call_op(0x1000, [stack_varnode(), heap_varnode(),
                                          FakeVarnode(reg=True)])]
        CALLSITES["memcpy"] = {caller: [0x1000]}
        result = opa.single_out_param_analysis("memcpy", 1, src_size_param_no=3,
                                               src_param_no=2, program=FakeProgram())
        self.assertIsInstance(result, opa.FuncOutParamAnalysisDesc)
        self.assertEqual(result.stack_dest_var_or_no_src_size_by_func[caller], {0x1000})


class TestCallsiteCaching(unittest.TestCase):
    def setUp(self):
        reset()

    def test_empty_result_is_cached(self):
        # the lookup scans every function in the program, so an empty
        # result must not trigger a repeat scan
        d = desc(func_name="nowhere", out_param_no=1)
        d.get_callsites(program=None)
        d.get_callsites(program=None)
        self.assertEqual(CALLSITE_LOOKUPS["nowhere"], 1)

    def test_cache_is_per_program(self):
        d = desc(func_name="memcpy", out_param_no=1)
        d.get_callsites(program=FakeProgram("a"))
        d.get_callsites(program=FakeProgram("b"))
        self.assertEqual(CALLSITE_LOOKUPS["memcpy"], 2)

    def test_same_program_reuses_cache(self):
        program = FakeProgram("a")
        d = desc(func_name="memcpy", out_param_no=1)
        d.get_callsites(program=program)
        d.get_callsites(program=program)
        self.assertEqual(CALLSITE_LOOKUPS["memcpy"], 1)

    def test_callsites_property_still_works(self):
        caller = FakeFunction("caller")
        CALLSITES["memcpy"] = {caller: [0x1000]}
        self.assertEqual(desc(func_name="memcpy", out_param_no=1).callsites,
                         {caller: [0x1000]})


class TestDefaultDescriptors(unittest.TestCase):
    def test_module_level_collection(self):
        names = [d.func_name for d in opa.desc_col.analysis_descs]
        self.assertIn("memcpy", names)
        self.assertIn("snprintf", names)
        for d in opa.desc_col.analysis_descs:
            self.assertEqual(d.out_param_no, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
