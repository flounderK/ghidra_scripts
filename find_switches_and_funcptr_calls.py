from __main__ import *
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.pcode import PcodeOpAST
from collections import defaultdict

refman = currentProgram.getReferenceManager()

target_ops = [PcodeOpAST.BRANCHIND, PcodeOpAST.CALLIND]
func_to_op_count = defaultdict(lambda: 0)
func_to_op = defaultdict(list)
listing = currentProgram.getListing()
last_op = None
for instr in listing.getInstructions(True):
    raw_ops = list(instr.getPcode())
    for op in raw_ops:
        if not op.opcode in target_ops:
            last_op = op.opcode
            continue
        
        refs = refman.getReferencesFrom(op.seqnum.target)

        # account for the case where something like an int3 occurred, which expands to a 
        # CALLOTHER followed by a CALLIND with no to references
        if last_op == PcodeOpAST.CALLOTHER and len(refs) == 0:
            last_op = op.opcode
            continue
        
        # calls to imported functions are performed with a computed call or jump, so these need to 
        # be filtered out
        ext_call_ref_found = False
        for ref in refs:
            if ref.referenceType in [FlowType.COMPUTED_CALL, FlowType.COMPUTED_JUMP] and ref.isExternalReference():
                ext_call_ref_found = True
                break
        if ext_call_ref_found:
            last_op = op.opcode
            continue

        func = getFunctionContaining(op.seqnum.target)
        func_to_op_count[func] += 1
        func_to_op[func].append(op)
        last_op = op.opcode


func_to_op_count_list = list(func_to_op_count.items())
func_to_op_count_list.sort(key=lambda a: a[1], reverse=True)

for func, num_cmps in func_to_op_count_list[:100]:
    print("%s : %d" % (func, num_cmps))