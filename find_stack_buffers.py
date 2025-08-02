from __main__ import *
from ghidra.program.model.pcode import PcodeOpAST


def getStackRegister(program=None):
    if program is None:
        program = currentProgram
    return program.getCompilerSpec().getStackPointer()


def get_functions_with_stack_sub():
    sp = getStackRegister()
    sp_off = sp.getOffset()
    dtm = currentProgram.getDataTypeManager()
    listing = currentProgram.getListing()
    addrs = set()
    for instr in listing.getInstructions(1):
        pcode_ops = list(instr.getPcode())
        for op in pcode_ops:
            if op.opcode != PcodeOpAST.INT_SUB:
                continue
            outp = op.getOutput()
            if outp is None:
                continue
            if not outp.isRegister():
                continue
            if outp.getOffset() != sp_off:
                continue
            if not any([inp for inp in op.getInputs() if inp.isRegister() and inp.getOffset() == sp_off]):
                continue
            addrs.add(instr.address)
    funcs_with_stack_adjust = [getFunctionContaining(addr) for addr in addrs]
    funcs_with_stack_adjust = list(set([i for i in funcs_with_stack_adjust if i is not None]))
    funcs_with_stack_adjust.sort(key=lambda a: a.name)
    return funcs_with_stack_adjust


if __name__ == "__main__":
    funcs_with_stack_adjust = get_functions_with_stack_sub()
    for func in funcs_with_stack_adjust:
        print(func)

