# tag functions that are registering callback functions
#@author Clifton Wolfe
#@category Analysis

from __main__ import *
from collections import defaultdict
from ghidra.program.model.symbol import SourceType


def get_function_data_refs_from_funcs(program=None):
    if program is None:
        program = currentProgram
    data_refs_from_funcs = defaultdict(list)
    refman = program.getReferenceManager()
    for func in program.getFunctionManager().getFunctions(1):
        refs = refman.getReferencesTo(func.getEntryPoint())
        for ref in refs:
            if not ref.referenceType.isData():
                continue
            referring_func = getFunctionContaining(ref.fromAddress)
            if referring_func is None:
                continue
            data_refs_from_funcs[referring_func].append(ref)
    return dict(data_refs_from_funcs)


def generate_placeholder_function_name(func, prefix):
    entrypoint = func.getEntryPoint()
    return "%s_%s" % (prefix, str(entrypoint))


def tag_callback_registration(program=None, rename_unnamed_referring_funcs=True, rename_unnamed_callback_funcs=True):
    if program is None:
        program = currentProgram
    function_data_refs = get_function_data_refs_from_funcs(program)

    for referring_func, refs in function_data_refs.items():
        referring_func.addTag("CALLBACK_REGISTRATION_FUNCTION")
        if rename_unnamed_referring_funcs is True and referring_func.name.startswith("FUN_"):
            generated_name = generate_placeholder_function_name(referring_func, "registerCallback")
            referring_func.setName(generated_name, SourceType.USER_DEFINED)

        for ref in refs:
            referenced_func = getFunctionContaining(ref.toAddress)
            if referenced_func is None:
                continue
            referenced_func.addTag("CALLBACK_FUNTION")
            if rename_unnamed_callback_funcs is True and referenced_func.name.startswith("FUN_"):
                generated_name = generate_placeholder_function_name(referenced_func, "callback")
                referenced_func.setName(generated_name, SourceType.USER_DEFINED)



if __name__ == "__main__":
    tag_callback_registration(currentProgram)
