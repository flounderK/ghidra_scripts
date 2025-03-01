from __main__ import *
from decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
from collections import defaultdict
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)


ucmp_opcodes = [PcodeOpAST.INT_LESS, PcodeOpAST.INT_LESSEQUAL]

cmpsites = defaultdict(list)
du = DecompUtils()

for func in currentProgram.getFunctionManager().getFunctions(1):
    log.debug("looking at %s" % func.name)
    pcode_ops = du.get_pcode_for_function(func)
    ucmp_insts = [i for i in pcode_ops if i.opcode in ucmp_opcodes]
    for inst in ucmp_insts:
        # TODO: this might only matter if it is the second input
        for inp in inst.inputs:
            back_slice_ops = DecompilerUtils.getBackwardSliceToPCodeOps(inp)
            if PcodeOpAST.INT_SUB in [i.opcode for i in back_slice_ops]:
                cmpsites[func].append(inst.seqnum.getTarget())
                # only care to find the cmp site, so skip the next one
                # on success
                break

for func, addrs in cmpsites.items():
    print(func)
    for addr in addrs:
        print(addr)
    print("")
