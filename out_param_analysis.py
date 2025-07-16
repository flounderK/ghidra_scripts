from __main__ import *
from call_ref_utils import get_callsites_for_func_by_name
from collections import defaultdict
from decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
from register_utils import getStackRegister
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)


class OutParamAnalysisResult:
    def __init__(self, func_name, args=None):
        self.func_name = func_name
        if args:
            self.args = args
        else:
            self.args = []
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


def out_param_analysis(func_name, out_param_no, src_size_param_no=None, dest_size_param_no=None, src_param_no=None, program=None):
    if program is None:
        program = currentProgram
    stack_reg_offset = getStackRegister().getOffset()

    du = DecompUtils(program=program)
    args = [out_param_no, src_size_param_no, dest_size_param_no, src_param_no]
    opar = OutParamAnalysisResult(func_name, args)

    callsites = get_callsites_for_func_by_name(func_name, program=program)
    for calling_func, call_addrs in callsites.items():
        pcode_ops = du.get_pcode_for_function(calling_func)
        call_ops = [i for i in pcode_ops if i.opcode == PcodeOpAST.CALL and i.seqnum.target in call_addrs]
        for op in call_ops:
            stack_dest = False
            stack_src = False
            const_or_addr_dest = False
            # TODO: an addr src from a rw region is still useful if size is not const
            const_or_addr_src = False
            var_dest_size = False
            # variable src size can be considered to be true if it isn't existent because that means that the size is inferred
            var_src_size = False
            if src_size_param_no is None:
                var_src_size = True
            var_dest = False
            var_src = False
            if src_param_no is None:
                var_src = True
            # gather attribute info about the call and the parameters to it that we care about
            if src_size_param_no is not None:
                inp = op.getInput(src_size_param_no)
                if inp is not None:
                    if inp.isConstant() is False:
                        var_src_size = True
            if dest_size_param_no is not None:
                inp = op.getInput(dest_size_param_no)
                if inp is not None:
                    if inp.isConstant() is False:
                        var_dest_size = True
            if src_param_no is not None:
                inp = op.getInput(src_param_no)
                if inp is not None:
                    if inp.isConstant() is True or inp.isAddress() is True:
                        const_or_addr_src = True
                    else:
                        var_src = True
                    back_slice_vns = DecompilerUtils.getBackwardSlice(inp)
                    if any([vn for vn in back_slice_vns if vn.isRegister() and int(vn.getOffset()) == stack_reg_offset]):
                        stack_src = True
            if out_param_no is not None:
                inp = op.getInput(out_param_no)
                if inp is not None:
                    if inp.isConstant() is True or inp.isAddress() is True:
                        const_or_addr_dest = True
                    else:
                        var_dest = True
                    back_slice_vns = DecompilerUtils.getBackwardSlice(inp)
                    if any([vn for vn in back_slice_vns if vn.isRegister() and int(vn.getOffset()) == stack_reg_offset]):
                        stack_dest = True
            # group this particular call based on gathered attributes
            # memcpy_s
            if stack_dest and var_dest_size:
                opar.stack_dest_var_dest_size_by_func[calling_func].add(op.seqnum.target)

            # memcpy or strcpy
            if stack_dest and var_src_size:
                opar.stack_dest_var_or_no_src_size_by_func[calling_func].add(op.seqnum.target)

            # memcpy or strcpy, but could lead to an info leak
            if stack_src and var_src_size:
                opar.stack_src_var_or_no_src_size_by_func[calling_func].add(op.seqnum.target)

            # all param: needs additional analysis
            if var_dest and var_src_size and (dest_size_param_no is None or var_dest_size is True) and var_src:
                opar.all_params_var_by_func[calling_func].add(op.seqnum.target)

            # possible overflow in a global
            if const_or_addr_dest and var_src_size:
                opar.const_dest_var_or_no_src_size_by_func[calling_func].add(op.seqnum.target)

    return opar

