# Auto-rename current function based on data accesses made within that function
#@author Clifton Wolfe
#@category C++
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript

from __main__ import *
from function_renamer import FunctionRenamer


def main():
    fr = FunctionRenamer(currentProgram)
    func = fr.fm.getFunctionAt(currentLocation.getFunctionEntryPoint())
    fr.rename_function_from_accessed_strings_guess(func)


if __name__ == "__main__":
    main()