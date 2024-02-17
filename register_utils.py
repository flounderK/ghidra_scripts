
from __main__ import *


def getStackRegister(program=None):
    if program is None:
        program = currentProgram
    return program.getCompilerSpec().getStackPointer()
