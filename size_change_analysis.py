from __main__ import *
from ghidra_api.call_ref_utils import get_callsites_for_func_by_name
from collections import defaultdict
from ghidra_api.decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)


#: Pcode ops that change a value's size or width on the way to its use. Arithmetic
#: (add/sub/multiply/shift) can overflow; PIECE/SUBPIECE and ZEXT/SEXT truncate or
#: extend; INT_AND masks. A size argument whose backward slice passes through any
#: of these was computed rather than passed through unchanged.
SIZE_CHANGING_OPCODES = frozenset([
    PcodeOpAST.INT_ADD, PcodeOpAST.INT_SUB,
    PcodeOpAST.INT_MULT, PcodeOpAST.INT_LEFT,
    PcodeOpAST.PIECE, PcodeOpAST.SUBPIECE,
    PcodeOpAST.INT_ZEXT, PcodeOpAST.INT_SEXT,
    PcodeOpAST.INT_AND,
])

#: The subset that can wrap a size to a smaller value -- the integer-overflow
#: shape of CWE-190 (``attacker * sizeof``, ``1 << n``).
OVERFLOW_OPCODES = frozenset([PcodeOpAST.INT_MULT, PcodeOpAST.INT_LEFT])


def varnode_size_change_ops(varnode):
    """The size-changing pcode opcodes a varnode's backward slice passes through.

    Returns a set drawn from ``SIZE_CHANGING_OPCODES`` (plus a truncating or
    extending LOAD/COPY), or an empty set when the value is a constant/address or
    reaches its use unchanged. A caller vetting an allocation size treats an
    intersection with ``OVERFLOW_OPCODES`` as the integer-overflow shape.
    """
    if varnode is None or varnode.isConstant() or varnode.isAddress():
        return set()
    back_slice = DecompilerUtils.getBackwardSliceToPCodeOps(varnode) or []
    ops = {op.opcode for op in back_slice if op.opcode in SIZE_CHANGING_OPCODES}
    for op in back_slice:
        if op.opcode in (PcodeOpAST.LOAD, PcodeOpAST.COPY) and \
                op.getInput(0).getSize() != op.getOutput().getSize():
            ops.add(op.opcode)
            break
    return ops


def simple_size_changing_check(func_name, argument_no, program=None):
    """Callsites of ``func_name`` whose argument ``argument_no`` was size-changed.

    ``argument_no`` indexes the CALL op's inputs, so 1 is the first C argument.
    """
    if program is None:
        program = currentProgram
    call_locs = defaultdict(list)
    du = DecompUtils(program=program)
    callsites = get_callsites_for_func_by_name(func_name, program=program)
    for calling_func, call_addrs in callsites.items():
        pcode_ops = du.get_pcode_for_function(calling_func)
        call_ops = [i for i in pcode_ops
                    if i.opcode == PcodeOpAST.CALL and i.seqnum.target in call_addrs]
        for op in call_ops:
            if argument_no >= op.getNumInputs():
                continue
            if varnode_size_change_ops(op.getInput(argument_no)):
                call_locs[calling_func].append(op.seqnum.target)
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
