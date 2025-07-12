from __main__ import *
from call_ref_utils import get_callsites_for_func_by_name
from collections import defaultdict
from decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)


def simple_size_changing_check(func_name, argument_no, program=None):
    if program is None:
        program = currentProgram
    call_locs = defaultdict(list)
    du = DecompUtils(program=program)
    callsites = get_callsites_for_func_by_name(func_name, program=program)
    for calling_func, call_addrs in callsites.items():
        pcode_ops = du.get_pcode_for_function(calling_func)
        call_ops = [i for i in pcode_ops if i.opcode == PcodeOpAST.CALL and i.seqnum.target in call_addrs]
        for op in call_ops:
            vn.getInput(argument_no)
            if vn.isConstant() or vn.isAddress():
                continue
            back_slice = DecompilerUtils.getBackwardSliceToPCodeOps(vn)
            if any([i.opcode in [PcodeOpAST.INT_ADD, PcodeOpAST.INT_SUB] for i in back_slice]):
                call_locs[calling_funcs].append(op.seqnum.target)
                continue
            if any([i.opcode in [PcodeOpAST.PIECE, PcodeOpAST.SUBPIECE] for i in back_slice]):
                call_locs[calling_funcs].append(op.seqnum.target)
                continue
            if any([i.opcode in [PcodeOpAST.INT_ZEXT, PcodeOpAST.INT_SEXT] for i in back_slice]):
                call_locs[calling_funcs].append(op.seqnum.target)
                continue
            if any([i.opcode in [PcodeOpAST.INT_AND] for i in back_slice]):
                call_locs[calling_funcs].append(op.seqnum.target)
                continue
            if any([i for i in back_slice if i.opcode in [PcodeOpAST.LOAD, PcodeOpAST.COPY] and i.getInput(0).getSize() != i.getOutput().getSize()]):
                call_locs[calling_funcs].append(op.seqnum.target)
                continue
    return dict(call_locs)


if __name__ == "__main__":
    func_name = askString("name of function", "select")
    func_size_argument_no = askInt("size arg no", "size arg no indexed from 1")
    call_locs = simple_size_changing_check(func_name, func_size_argument_no)
    for calling_func, op_addrs in call_locs.items():
        print(calling_func)
        for addr in op_addrs:
            try:
                createBookmark(addr, "%s: size change before usage" % func_name, "")
            except:
                pass
            print(addr)
        print("")
