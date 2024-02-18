from __main__ import *

from ghidra.app.script import GhidraScript
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.data import Category
from ghidra.program.model.data import CategoryPath
from ghidra.program.model.data import DataType
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.data import ProgramBasedDataTypeManager
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import ParameterDefinition
from ghidra.program.model.data import ParameterDefinitionImpl
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import FunctionIterator
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.listing import FunctionSignature
from ghidra.program.model.listing import Program
from ghidra.program.model.symbol import SourceType
from ghidra.program.database.data import DataTypeUtilities
from ghidra.program.model.data import DefaultDataType
from ghidra.program.model.data import MetaDataType

from datatype_utils import getUndefinedRegisterSizeDatatype


def getDataTypeForParam(func, param_num):
    sig = func.getSignature()
    param_ind = param_num - 1
    if param_ind < 0:
        raise Exception("param_num is too low to be valid")
    args = list(sig.getArguments())
    if len(args) <= param_ind:
        return None
    param = args[param_ind]
    existing_datatype = param.getDataType()
    return existing_datatype


def set_num_params(func, num_params, widen_undef_params=True, widen_undef_return=False, default_datatype=None, var_args=False, program=None):
    """
    Set the number of parameters for a function. 
    """
    if program is None:
        program = currentProgram

    if default_datatype is None:
        default_datatype = getUndefinedRegisterSizeDatatype(program)

    existing_sig = func.getSignature()
    existing_args = list(existing_sig.getArguments())
    existing_args_len = len(existing_args)
    # create a list of parameters
    params = []
    for i in range(num_params):
        if i < existing_args_len:
            param = existing_args[i]
            if widen_undef_params is True:
                dt = param.getDataType()
                if isinstance(dt, DefaultDataType):
                    param.setDataType(default_datatype)
        else:
            param_name = "param_%d" % (i+1)
            param_dt = default_datatype
            param_comment = ""
            param = ParameterDefinitionImpl(param_name, param_dt, param_comment)
        params.append(param)

    existing_sig.setArguments(params)
    if var_args is True:
        existing_args.setVarArgs(True)

    if widen_undef_return is True:
        return_type = existing_sig.getReturnType()
        if isinstance(return_type, DefaultDataType):
            existing_sig.setReturnType(default_datatype)
    # FunctionSignature newSignature = func_def
    cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), existing_sig, SourceType.USER_DEFINED)
    return runCommand(cmd)


def set_param_datatype(func, param_num, datatype, program=None):
    """
    Sets the Datatype for a parameter
    param_num is indexed from 1 and matches the param_* that can be seen in the decompiler.
    """
    param_ind = param_num-1
    if param_ind < 0:
        raise Exception("parameter number is too low")
    if program is None:
        program = currentProgram
    default_datatype = getUndefinedRegisterSizeDatatype(program)
    existing_sig = func.getSignature()
    existing_args = list(existing_sig.getArguments())
    existing_args_len = len(existing_args)
    # create a list of parameters
    params = []
    for i in range(max(existing_args_len, param_ind)):
        if i >= existing_args_len:
            param_name = "param_%d" % (i+1)
            if param_ind == i:
                param_dt = datatype
            else:
                param_dt = default_datatype
            param_comment = ""
            param = ParameterDefinitionImpl(param_name, param_dt, param_comment)
        else:
            param = existing_args[i]
            if i == param_ind:
                param.setDataType(datatype)
        params.append(param)

    existing_sig.setArguments(params)
    cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), existing_sig, SourceType.USER_DEFINED)
    return runCommand(cmd)