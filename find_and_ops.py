from __main__ import *
from ghidra.program.model import PcodeOpAST
from ghidra.program.database.code import InstructionDB
from ghidra.program.model.symbol import RefType, SourceType, MemReferenceImpl
from collections import defaultdict
import struct
import re

funcs_to_opaddrs = defaultdict(list)
listing = currentProgram.getListing()
instructions = listing.getInstructions(True)
for instr in instructions:
    for raw_ops in instr.getPcode():
        for op in raw_ops:
            if op.opcode == PcodeOpAST.INT_AND:
                addr = op.seqnum.target
                func = getFunctionContaining(addr)
                funcs_to_opaddrs[func].append(addr)

for func, addrs in funcs_to_opaddrs.items():
    print(func)
    for addr in addrs:
        print(addr)
    print("")
