from __main__ import *
from ghidra.program.util import DefinedDataIterator
import re
from collections import defaultdict
from ghidra.program.model.symbol import SymbolType, SourceType
from call_ref_utils import get_callsites_for_func_by_name
from decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils


def get_func_to_string_data_mapping():
    program = currentProgram
    # data_iter = DefinedDataIterator(program)
    listing = program.getListing()
    data_iter = listing.getDefinedData(1)
    refman = program.getReferenceManager()
    string_data_list = []
    while data_iter.hasNext():
        data = data_iter.next()
        string_value = data.getValue()
        if string_value is None:
            continue
        if not isinstance(string_value, (str, unicode)):
            continue
        string_data_list.append(data)

    string_to_funcs_mapping = defaultdict(set)
    for data in string_data_list:
        string_val = data
        # get functions referencing the path
        for ref in refman.getReferencesTo(data.getAddress()):
            func = getFunctionContaining(ref.fromAddress)
            if func is None:
                continue
            string_to_funcs_mapping[func].add(string_val)
    return string_to_funcs_mapping


def rename_functions_from_called_function_string_arg(func_name, arg_num):
    func_to_string_mapping = get_func_to_string_data_mapping()

    du = DecompUtils()
    refman = currentProgram.getReferenceManager()
    callsites = get_callsites_for_func_by_name(func_name)
    # arg_num = 3
    for calling_func, call_addrs in callsites.items():
        if not calling_func.name.startswith("FUN_"):
            continue
        pcode_ops = du.get_pcode_for_function(calling_func)
        call_ops = [i for i in pcode_ops if i.opcode == PcodeOpAST.CALL and i.seqnum.target in call_addrs]
        for call_op in call_ops:
            back_slice = list(DecompilerUtils.getBackwardSliceToPCodeOps(call_op.getInput(arg_num)))
            for op in back_slice:
                for ref in refman.getReferencesFrom(op.seqnum.target):
                    for dat in func_to_string_mapping[calling_func]:
                        if ref.toAddress != dat.address:
                            continue
                        string_value = dat.getValue()
                        if string_value is None:
                            continue
                        if not isinstance(string_value, (str, unicode)):
                            continue
                        new_name = string_value + "_" + str(calling_func.entryPoint)
                        calling_func.setName(new_name, SourceType.USER_DEFINED)
                        


if __name__ == "__main__":
    func_name = askString("function name", "function name")
    arg_num = askInt("arg num", "arg num")
    rename_functions_from_called_function_string_arg(func_name, arg_num)