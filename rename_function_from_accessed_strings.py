from __main__ import *
from ghidra.program.util import DefinedDataIterator
import re
from collections import defaultdict
from ghidra.program.model.symbol import SymbolType, SourceType


def get_string_to_func_mapping(rexp):
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
        m = re.search(rexp, string_value)
        if m is None:
            continue
        string_data_list.append(data)

    string_to_funcs_mapping = defaultdict(set)
    for data in string_data_list:
        string_val = data.getValue()
        # get functions referencing the path
        for ref in refman.getReferencesTo(data.getAddress()):
            func = getFunctionContaining(ref.fromAddress)
            if func is None:
                continue
            string_to_funcs_mapping[string_val].add(func)
    return string_to_funcs_mapping


rexp = askString("rexp", "rexp")

string_to_funcs_mapping = get_string_to_func_mapping(rexp)
for string_val, funcs in string_to_funcs_mapping.items():
    for func in funcs:
        if not func.name.startswith("FUN_"):
            continue
        func_name_prefix = re.search(rexp, string_val).groups()[0]
        print("chose %s from %s" % (func_name_prefix, string_val))
        func_name_prefix = func_name_prefix.replace(".", "_")
        new_name = func_name_prefix + "_" + str(func.entryPoint)
        func.setName(new_name, SourceType.USER_DEFINED)
    
