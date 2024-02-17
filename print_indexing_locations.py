# Print all of the locations in the binary where indexing can be detected
#

from __main__ import *
from decomp_utils import find_all_pcode_op_instances
from ghidra.program.model.pcode import PcodeOpAST

funcs_with_ptradd = find_all_pcode_op_instances(PcodeOpAST.PTRADD)

# for func, ptradd_addrs in funcs_with_ptradd.items():
#     # print("%s" % func.name)
#     for addr in ptradd_addrs:
#         print("%s" % str(addr))
#     print("")
all_addrs = sum([v for v in funcs_with_ptradd.values()], [])
all_addrs.sort()
for addr in all_addrs:
    print("%s" % str(addr))
