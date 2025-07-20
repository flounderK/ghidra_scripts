from __main__ import *
from ghidra.program.model.pcode import PcodeOpAST
from collections import defaultdict

bad_consts = [0, 1, 2, -1, 0xffffffff, 0xffffffffffffffff]
cmp_ops = [PcodeOpAST.INT_EQUAL, PcodeOpAST.INT_LESS, PcodeOpAST.INT_LESSEQUAL, PcodeOpAST.INT_NOTEQUAL, PcodeOpAST.INT_SLESS, PcodeOpAST.INT_SLESSEQUAL]
func_to_cmp_count = defaultdict(lambda: 0)
func_to_cmp_op = defaultdict(list)
listing = currentProgram.getListing()
for instr in listing.getInstructions(True):
    raw_ops = list(instr.getPcode())
    for op in raw_ops:
        if not op.opcode in cmp_ops:
            continue
        skip_op = False
        for inp in op.getInputs():
            if inp.isConstant() and inp.getOffset() in bad_consts:
                skip_op = True
                break
        if skip_op:
            continue
        func = getFunctionContaining(op.seqnum.target)
        func_to_cmp_count[func] += 1
        # func_to_cmp_op[func].append(op)


func_to_cmp_count_list = list(func_to_cmp_count.items())
func_to_cmp_count_list.sort(key=lambda a: a[1], reverse=True)

for func, num_cmps in func_to_cmp_count_list[:100]:
    print("%s : %d" % (func, num_cmps))