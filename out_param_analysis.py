from __main__ import *
from ghidra_api.call_ref_utils import get_callsites_for_func_by_name
from collections import defaultdict
from ghidra_api.decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra_api.register_utils import getStackRegister
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)


class FuncOutParamAnalysisDesc(object):
    def __init__(self, func_name, out_param_no=None, src_size_param_no=None, dest_size_param_no=None, src_param_no=None):
        self.func_name = func_name
        self.out_param_no = out_param_no
        self.src_size_param_no = src_size_param_no
        self.dest_size_param_no = dest_size_param_no
        self.src_param_no = src_param_no
        self._callsites = None
        self._callsites_program = None
        # memcpy_s
        self.stack_dest_var_dest_size_by_func = defaultdict(set)
        # memcpy or strcpy
        self.stack_dest_var_or_no_src_size_by_func = defaultdict(set)
        # memcpy or strcpy, but could lead to an info leak
        self.stack_src_var_or_no_src_size_by_func = defaultdict(set)
        # all param: needs additional analysis
        self.all_params_var_by_func = defaultdict(set)
        # possible overflow in a global
        self.const_dest_var_or_no_src_size_by_func = defaultdict(set)
        # mapping of which parameter indexes are sourced from the caller functions parameters
        # caller func: {call_addr: [(func_name param no, caller_func param no),]}
        self.param_to_caller_param_map = defaultdict(dict)

    def get_callsites(self, program=None):
        """
        Return {Function: [call address, ..]} for calls to this function,
        looked up once per program and cached. An empty result is cached too,
        since the lookup scans every function in the program
        """
        if self._callsites is None or self._callsites_program is not program:
            self._callsites = get_callsites_for_func_by_name(self.func_name, program=program)
            self._callsites_program = program
        return self._callsites

    @property
    def callsites(self):
        return self.get_callsites()


class OutParamAnalysisCollection(object):
    def __init__(self, analysis_descs=None):
        # a list of FuncOutParamAnalysisDesc objects
        self.analysis_descs = analysis_descs if analysis_descs is not None else []

    def get_calling_func_to_desc_map(self, program=None):
        """
        Return a mapping of calling func to FuncOutParamAnalysisDesc object
        """
        res = defaultdict(list)
        for desc in self.analysis_descs:
            for calling_func in desc.get_callsites(program=program).keys():
                res[calling_func].append(desc)
        return dict(res)


class CallParamAttributes(object):
    """
    Attributes of a single call, gathered from the parameters we care about
    """

    __slots__ = ("stack_dest", "stack_src", "const_or_addr_dest",
                 "var_dest_size", "var_src_size", "var_dest", "var_src")

    def __init__(self, desc):
        self.stack_dest = False
        self.stack_src = False
        self.const_or_addr_dest = False
        self.var_dest_size = False
        # variable src size can be considered to be true if it isn't existent
        # because that means that the size is inferred
        self.var_src_size = desc.src_size_param_no is None
        self.var_dest = False
        self.var_src = desc.src_param_no is None


def _is_stack_derived(varnode, stack_reg_offset):
    """
    True if @varnode is reached from the stack pointer register
    """
    back_slice_vns = DecompilerUtils.getBackwardSlice(varnode)
    return any([vn for vn in back_slice_vns
                if vn.isRegister() and int(vn.getOffset()) == stack_reg_offset])


def get_call_param_attributes(op, desc, stack_reg_offset):
    """
    Gather attribute info about the call @op and the parameters to it that we
    care about, as described by @desc
    """
    attrs = CallParamAttributes(desc)

    if desc.src_size_param_no is not None:
        inp = op.getInput(desc.src_size_param_no)
        if inp is not None:
            if inp.isConstant() is False:
                attrs.var_src_size = True

    if desc.dest_size_param_no is not None:
        inp = op.getInput(desc.dest_size_param_no)
        if inp is not None:
            if inp.isConstant() is False:
                attrs.var_dest_size = True

    if desc.src_param_no is not None:
        inp = op.getInput(desc.src_param_no)
        if inp is not None:
            # TODO: an addr src from a rw region is still useful if size is not const
            if not (inp.isConstant() is True or inp.isAddress() is True):
                attrs.var_src = True
            if _is_stack_derived(inp, stack_reg_offset):
                attrs.stack_src = True

    if desc.out_param_no is not None:
        inp = op.getInput(desc.out_param_no)
        if inp is not None:
            if inp.isConstant() is True or inp.isAddress() is True:
                attrs.const_or_addr_dest = True
            else:
                attrs.var_dest = True
            if _is_stack_derived(inp, stack_reg_offset):
                attrs.stack_dest = True

    return attrs


def record_call(desc, calling_func, call_addr, attrs):
    """
    Group the call at @call_addr based on the attributes gathered for it
    """
    # memcpy_s
    if attrs.stack_dest and attrs.var_dest_size:
        desc.stack_dest_var_dest_size_by_func[calling_func].add(call_addr)

    # memcpy or strcpy
    if attrs.stack_dest and attrs.var_src_size:
        desc.stack_dest_var_or_no_src_size_by_func[calling_func].add(call_addr)

    # memcpy or strcpy, but could lead to an info leak
    if attrs.stack_src and attrs.var_src_size:
        desc.stack_src_var_or_no_src_size_by_func[calling_func].add(call_addr)

    # all param: needs additional analysis
    if attrs.var_dest and attrs.var_src_size and attrs.var_src and \
            (desc.dest_size_param_no is None or attrs.var_dest_size is True):
        desc.all_params_var_by_func[calling_func].add(call_addr)

    # possible overflow in a global
    if attrs.const_or_addr_dest and attrs.var_src_size:
        desc.const_dest_var_or_no_src_size_by_func[calling_func].add(call_addr)


def _get_call_ops_by_target(du, calling_func):
    """
    Return {call target address: [PcodeOpAST, ..]} for the CALL ops in
    @calling_func, or None if it could not be decompiled
    """
    pcode_ops = du.get_pcode_for_function(calling_func)
    if pcode_ops is None:
        return None
    call_ops_by_target = defaultdict(list)
    for op in pcode_ops:
        if op.opcode == PcodeOpAST.CALL:
            call_ops_by_target[op.seqnum.target].append(op)
    return call_ops_by_target


def out_param_analysis(desc_col, program=None):
    """
    OutParamAnalysisCollection
    """
    if program is None:
        program = currentProgram

    stack_reg_offset = getStackRegister(program=program).getOffset()
    du = DecompUtils(program=program)
    for calling_func, descs in desc_col.get_calling_func_to_desc_map(program=program).items():
        # decompile each calling function once, no matter how many descs it
        # has callsites for
        call_ops_by_target = _get_call_ops_by_target(du, calling_func)
        if call_ops_by_target is None:
            log.warning("skipping %s, no pcode available" % calling_func.name)
            continue
        for desc in descs:
            for call_addr in desc.get_callsites(program=program)[calling_func]:
                for op in call_ops_by_target.get(call_addr, []):
                    attrs = get_call_param_attributes(op, desc, stack_reg_offset)
                    record_call(desc, calling_func, call_addr, attrs)

    return desc_col


def single_out_param_analysis(func_name, out_param_no, src_size_param_no=None, dest_size_param_no=None, src_param_no=None, program=None):
    opar = FuncOutParamAnalysisDesc(func_name, out_param_no, src_size_param_no, dest_size_param_no, src_param_no)
    out_param_analysis(OutParamAnalysisCollection([opar]), program=program)
    return opar


desc_col = OutParamAnalysisCollection()
desc_col.analysis_descs = [
    FuncOutParamAnalysisDesc("memcpy", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("memmove", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("wmemmove", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("wmemcpy", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("memcpy_s", out_param_no=1,
                             src_size_param_no=4,
                             dest_size_param_no=2, src_param_no=3),
    FuncOutParamAnalysisDesc("wmemcpy_s", out_param_no=1,
                             src_size_param_no=4,
                             dest_size_param_no=2, src_param_no=3),
    FuncOutParamAnalysisDesc("strcpy", out_param_no=1,
                             src_size_param_no=None,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("strncpy", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("sprintf", out_param_no=1,
                             src_size_param_no=None,
                             dest_size_param_no=None,
                             src_param_no=None),
    FuncOutParamAnalysisDesc("snprintf", out_param_no=1,
                             src_size_param_no=None,
                             dest_size_param_no=2,
                             src_param_no=None),
]
