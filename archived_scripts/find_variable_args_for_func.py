
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript
from argument_analyzer import *
import logging

from __main__ import *


func_name = askString("Function Name", "Enter Function Name")
param_ind = askInt("Parameter Index", "Enter parameter index (indexed from 0)")

aa = FunctionArgumentAnalyzer(currentProgram)
call_ops_for_target = aa.get_pcode_calling_ops_by_func_name(func_name)
complex_call_ops = aa.filter_calls_with_simple_param(call_ops_for_target, param_ind)

complex_call_ops.sort(key=lambda op: getFunctionContaining(op.seqnum.target).name)

for call_op in complex_call_ops:
    caller_func = getFunctionContaining(call_op.seqnum.target)
    print("%s in %s" % (call_op.seqnum.target, caller_func.name))
