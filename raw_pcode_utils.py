from __main__ import *
from ghidra.program.model.address import AddressSet, AddressRangeImpl
from ghidra.program.util import ProgramSelection
from ghidra.program.model.pcode import PcodeOpAST
from collections import defaultdict


def get_raw_pcode_for_func(func):
    listing = currentProgram.getListing()
    instrs = list(listing.getInstructions(func.body, 1))
    raw_pcode_ops = [i for i in sum([list(i.getPcode()) for i in instrs], [])]
    return raw_pcode_ops


def get_addr_set_for_ops_in_func(func, target_opcodes):
    listing = currentProgram.getListing()
    raw_pcode_ops = get_raw_pcode_for_func(func)
    op_addrs = [i.seqnum.target for i in raw_pcode_ops if i.opcode in target_opcodes]
    target_instrs = [listing.getCodeUnitConaining(i) for i in op_addrs]
    addr_set = AddressSet()
    for inst in target_instrs:
        addr_set.add(AddressRangeImpl(inst.minAddress, inst.maxAddress))
    return addr_set


def select_ops_in_func(func, target_opcodes):
    addr_set = get_addr_set_for_ops_in_func(func, target_opcodes)
    state.setCurrentSelection(ProgramSelection(addr_set))


def get_funcs_to_op_addrs(target_opcodes):
    funcs_to_opaddrs = defaultdict(set)
    listing = currentProgram.getListing()
    instructions = listing.getInstructions(True)
    for instr in instructions:
        raw_ops = list(instr.getPcode())
        for op in raw_ops:
            if op.opcode not in target_opcodes:
                continue
            addr = op.seqnum.target
            func = getFunctionContaining(addr)
            funcs_to_opaddrs[func].add(addr)
    funcs_to_opaddrs = {k: list(v) for k, v in funcs_to_opaddrs.items()}
    return funcs_to_opaddrs


def get_func_op_freq_list(target_opcodes):
    funcs_to_opaddrs = get_funcs_to_op_addrs(target_opcodes)
    funcs_to_op_freq = {k: len(v) for k, v in funcs_to_opaddrs.items()}
    funcs_to_op_freq_list = list(funcs_to_op_freq.items())
    funcs_to_op_freq_list.sort(key=lambda a: a[1], reverse=True)
    return funcs_to_op_freq_list


