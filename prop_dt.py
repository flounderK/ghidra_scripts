# naively propagate a datatype forward to all function signatures it directly
# flows to
from __main__ import *

from type_propagator import propagate_datatype_forward_to_function_signatures
from decomp_utls import DecompUtils


def prop_datatype_from_func_param(func, param_num, program=None):
    if program is None:
        program = currentProgram

    sig = func.getSignature()
    args = list(sig.getArguments())
    dt = args[param_num-1].getDataType()
    du = DecompUtils(program)
    vns = du.get_varnodes_for_param(func, param_num)
    propagate_datatype_forward_to_function_signatures(vns, dt, program=program)


selection = currentSelection

if selection:
    addr = selection.minAddress
    func = getFunctionContaining(addr)
else:
    func_name = askString("enter function name", "enter function name")
    func = getFunction(func_name)

param_num = askInt("Parameter (indexed from 1)", "Parameter (indexed from 1)")

prop_datatype_from_func_param(func, param_num, program=currentProgram)
