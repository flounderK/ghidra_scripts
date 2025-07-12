from __main__ import *
from ghidra.program.util import DefinedDataIterator
import re
from collections import defaultdict
from ghidra.program.model.symbol import SymbolType

def get_source_file_to_func_mapping(rexp="\.c$"):
    program = currentProgram
    data_iter = DefinedDataIterator(program)
    refman = program.getReferenceManager()
    string_data_list = []
    while data_iter.hasNext():
        data = data_iter.next()
        string_value = data.getValue()
        if string_value is None:
            continue
        m = re.search(rexp, string_value)
        if m is None:
            continue
        string_data_list.append(data)

    source_file_to_func_mapping = defaultdict(set)
    for data in string_data_list:
        filepath = data.getValue()
        # get functions referencing the path
        for ref in refman.getReferencesTo(data.getAddress()):
            func = getFunctionContaining(ref.fromAddress)
            if func is None:
                continue
            source_file_to_func_mapping[filepath].add(func)
    return source_file_to_func_mapping


source_file_to_func_mapping = get_source_file_to_func_mapping()
for source_path, funcs in source_file_to_func_mapping.items():
    for func in funcs:
        if not func.name.startswith("FUN_"):
            continue
        start_offset = source_path.rfind("\\")
        if start_offset != -1:
            start_offset += 1
        else:
            start_offset = source_path.rfind("/")
            if start_offset != -1:
                start_offset += 1
        if start_offset == -1:
            start_offset = 0
        func_name_prefix = source_path[start_offset:]
        print("chose %s from %s" % (func_name_prefix, source_path))
        func_name_prefix = func_name_prefix.replace(".", "_")
        new_name = "related_to_" + func_name_prefix + "_" + str(func.entryPoint)
        func.setName(new_name, SourceType.USER_DEFINED)
    
