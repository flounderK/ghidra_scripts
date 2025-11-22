from __main__ import *
from ghidra.program.model.pcode import PcodeOpAST
from collections import defaultdict
from decomp_utils import DecompUtils
import logging


DO_DECOMPILE = False
log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)

refman = currentProgram.getReferenceManager()
target_ops = [PcodeOpAST.INT_XOR]

# initial pass for quickly finding all instances of the op
func_to_op_count = defaultdict(lambda: 0)
func_to_op = defaultdict(list)
func_to_addrs = defaultdict(list)
listing = currentProgram.getListing()
last_op = None
for instr in listing.getInstructions(True):
    raw_ops = list(instr.getPcode())
    for op in raw_ops:
        if not op.opcode in target_ops:
            last_op = op.opcode
            continue
        
        # filter out ops like xor eax, eax
        if op.getInput(0) == op.getInput(1):
            continue
        
        func = getFunctionContaining(op.seqnum.target)
        func_to_op_count[func] += 1
        func_to_op[func].append(op)
        func_to_addrs[func].append(op.seqnum.target)
        last_op = op.opcode


func_to_op_count_list = list(func_to_op_count.items())
func_to_op_count_list.sort(key=lambda a: a[1], reverse=True)

if DO_DECOMPILE is True:
    log.debug("%d functions to decompile. This stage can be disabled for better speed and worse accuracy" % len(func_to_op_count_list))

    # optional secondary pass to remove duds from refined pcode, like xor eax, eax being an INT_XOR instead of a zeroing equivalent
    du = DecompUtils()
    func_to_true_op_count = defaultdict(lambda: 0)
    func_to_true_op_addrs = defaultdict(list)
    func_to_true_op = defaultdict(list)
    for func, num_ops in func_to_op_count_list:
        if func is None:
            continue
        log.debug("decompiling %s" % str(func))
        pcode_ops = du.get_pcode_for_function(func)
        if pcode_ops is None:
            continue
        target_op_insts = [i for i in pcode_ops if i.opcode in target_ops]
        for op in target_op_insts:
            func_to_true_op_count[func] += 1
            func_to_true_op_addrs[func].append(op.seqnum.target)
            func_to_true_op[func].append(op)
        

    func_to_true_op_count_list = list(func_to_true_op_count.items())
    func_to_true_op_count_list.sort(key=lambda a: a[1], reverse=True)
    func_to_op = func_to_true_op
    func_to_addrs = func_to_true_op_addrs
    func_to_op_count = func_to_true_op_count
    func_to_op_count_list = func_to_true_op_count_list

# print things out

for func, num_cmps in func_to_op_count_list[:100]:
    addrs = func_to_addrs[func]
    print("%s : %d" % (func, num_cmps))



# print none addrs so that new functions can be defined
# none_addrs = func_to_addrs.get(None)
# if none_addrs:
#     print("None")
#     for addr in none_addrs:
#         print(addr)