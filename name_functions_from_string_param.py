# Auto-rename functions across a file based on the string passed to a specific function. 
# It should be noted that the script only works for functions whose names start with `FUN_`, 
# to avoid overwriting user-named functions.
# 
# It should also be noted that the script will only work if the parameter type has been 
# set correctly in the target function's signature. E.g. change `undefined8` to `char *`.
# 
# The script Is meant to be a quick and easy solution, and it does not actually emulate or 
# interpret pcode in a meaningful way, it just tracks writes to register and stack locations
# and relies on the assumption that in c and c++ a given space on the stack should only ever 
# be utilized for a single type E.g. a pointer on the stack that is used for a `char *` 
# should not ever be used to hold a `uint` unless there is a union containing the two types.
# Keeping that in mind, the script can and will rename things incorrectly
#@author Clifton Wolfe
#@category C++
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript

from __main__ import *
from function_renamer import FunctionRenamer


def main():
    fr = FunctionRenamer(currentProgram)
    funcname = askString("Which function's calls are you targeting? ", "")
    prompt = "Which parameter of %s? Please note that the argument types must be set correctly for this parameter" % funcname
    int1 = askInt(prompt, "enter parameter number")
    func = [i for i in fr.fm.getFunctions(1) if i.name == funcname][0]
    fr.rename_functions_by_function_call(func, int1)


if __name__ == "__main__":
    main()