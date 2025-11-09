from __main__ import *
from decomp_utils import find_all_pcode_op_instances
from ghidra.program.model.pcode import PcodeOpAST


op_insts = find_all_pcode_op_instances(PcodeOpAST.INT_XOR)

count_dict = {k: len(v) for k, v in op_insts.items()}
count_list = list(count_dict.items())
count_list.sort(key=lambda a: a[1], reverse=True)

for k, v in count_list:
    print("%s: %d" % (k, v))