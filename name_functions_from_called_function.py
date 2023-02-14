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


from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.program.util import FunctionSignatureFieldLocation
from ghidra.program.model.symbol import SourceType
from collections import namedtuple
import string

from __main__ import *


IncomingCallNode = namedtuple("IncomingCallNode", ["function", "call_address"])


def get_location(func):
    return FunctionSignatureFieldLocation(func.getProgram(), 
                                          func.getEntryPoint())


class FunctionRenamer:
    def __init__(self, currentProgram):
        self.fm = currentProgram.getFunctionManager()
        self.dtm = currentProgram.getDataTypeManager()
        self.namespace_manager = currentProgram.getNamespaceManager()
        self.addr_fact = currentProgram.getAddressFactory()
        self.addr_space = self.addr_fact.getDefaultAddressSpace()
        self.mem = currentProgram.getMemory()
        self.sym_tab = currentProgram.getSymbolTable()
        self._stack_reg_offset = currentProgram.getRegister("sp").getOffset()

        self.ptr_size = self.addr_space.getPointerSize()
        if self.ptr_size == 4:
            self._get_ptr_size = self.mem.getInt
        elif self.ptr_size == 8:
            self._get_ptr_size = self.mem.getLong

        self._null = self.addr_space.getAddress(0)
        self._global_ns = currentProgram.getGlobalNamespace()
        self._decomp_options = DecompileOptions()
        self._monitor = ConsoleTaskMonitor()
        self._ifc = DecompInterface()
        self._ifc.setOptions(self._decomp_options)
        self.refman = currentProgram.getReferenceManager()

    def get_high_function(self, func, timeout=60):
        """
        Get a HighFunction for a given function
        """
        self._ifc.openProgram(func.getProgram())
        res = self._ifc.decompileFunction(func, timeout, self._monitor)
        high_func = res.getHighFunction()
        return high_func
    
    def get_high_sym_for_param(self, func, param_num):
        """
        Get the the high sym for param index 
        """
        high_func = self.get_high_function(func)
        prototype = high_func.getFunctionPrototype()
        num_params = prototype.getNumParams()
        if num_params == 0:
            return None
        high_sym_param = prototype.getParam(param_num)
        return high_sym_param

    
    def get_callsites_for_function(self, func):
        location = get_location(func)
        references = list(ReferenceUtils.getReferenceAddresses(location, self._monitor))
        incoming_calls = []
        for call_address in references:
            self._monitor.checkCanceled()
            callerFunction = self.fm.getFunctionContaining(call_address)
            if callerFunction is None:
                continue
            incoming_calls.append(IncomingCallNode(callerFunction, call_address))
        return incoming_calls
    
    def get_previous_var_stack_offset_for_calling_function(self):
        pass

    def rename_functions_by_function_call(self, func, param_index):
        incoming_calls = self.get_callsites_for_function(func)
        additional_analysis_needed_funcs = set()
        incoming_functions = set([i.function for i in incoming_calls])
        for calling_func_node in incoming_functions:
            current_function_name = calling_func_node.getName()
            # calling_func_node = incoming_calls[1]
            hf = self.get_high_function(calling_func_node)
            pcode_ops = list(hf.getPcodeOps())
            func_address = func.getEntryPoint()

            call_ops = [i for i in pcode_ops if i.opcode == PcodeOpAST.CALL and i.getInput(0).getAddress() == func_address]
            if len(call_ops) == 0:
                print("no call found for %s" % current_function_name)
                continue
            # call_op = call_ops[0]
            copied_values = []
            param_def = None
            for call_op in call_ops:
                param_varnode = call_op.getInput(param_index+1)
                # check here if param is just the raw address. if not...
                try:
                    param_def = walk_pcode_until_handlable_op(param_varnode)
                except Exception as err:
                    # print(err)
                    additional_analysis_needed_funcs.add(calling_func_node)
                    continue
                copied_values += self.get_pcode_op_copy_operand(pcode_ops, param_def)

            if param_def is None:
                print("skipping %s" % current_function_name)
                continue
            # print("param def '%s'" % str(param_def))
            # there is a weird roundabout way of looking stuff up here because there is a varnode being compared 
            # with an arbitrary stackpointer offset
            # is_stackpointer_offset = any([i for i in param_def.getInputs() if i.isRegister() and i.getOffset() == self._stack_reg_offset])
            # for whatever reason, the created varnode here gets put into unique space, not stack space, 
            if len(copied_values) == 0:
                print("copied values for %s was empty" % current_function_name)
            possible_function_names = [self.read_string_at(i) for i in copied_values]
            best_function_name = self.choose_best_function_name(possible_function_names)
            # print("best function name %s" % best_function_name)
            # TODO: identify whether the `SourceType` of a function's name can be accessed so that names don't get overwritten
            if best_function_name is not None and current_function_name != best_function_name and \
                current_function_name.startswith("FUN_"):  # so that other user defined function names don't get overwritten
                print("changing name from %s to %s" % (current_function_name, best_function_name))
                calling_func_node.setName(best_function_name, SourceType.USER_DEFINED)    

        for i in additional_analysis_needed_funcs:
            print("\n** %s likely requires manual analysis or decompilation fixups" % i.getName())


    def read_string_at(self, address, maxsize=256):
        while maxsize > 0:
            try:
                string_bytearray = bytearray(getBytes(address, maxsize))
                extracted_string = string_bytearray[:string_bytearray.find(b'\x00')].decode()
                return extracted_string
            except:
                maxsize -= 1

    def get_pcode_op_copy_operand(self, pcode_ops, ptrsub_op):
        if ptrsub_op.opcode == PcodeOpAST.COPY:
            return [self.addr_space.getAddress(ptrsub_op.getInput(0).getOffset())]

        non_register_varnode = [i for i in ptrsub_op.getInputs() if not i.isRegister()][0]
        stack_offset = non_register_varnode.offset
        stackspace_id = self.addr_fact.getStackSpace().spaceID
        copied_values = []
        for op in pcode_ops:
            output = op.output
            if output is None:
                continue
            if output.offset != stack_offset:
                continue
            if output.getSpace() != stackspace_id:
                continue
            if op.opcode not in [PcodeOpAST.COPY]:
                continue
            # print("found one %s" % str(op))
            string_address = self.addr_space.getAddress(op.getInput(0).getOffset())
            copied_values.append(string_address)
        return copied_values
    
    def choose_best_function_name(self, function_name_candidates):
        possible_function_names = [i for i in function_name_candidates if i is not None and i.find(" ") == -1]
        if len(possible_function_names) == 0:
            return None
        if len(possible_function_names) == 1:
            return possible_function_names[0]

        printable_set = set(string.printable[:-5])
        punctuation_set = set(string.punctuation)
        possible_function_names.sort(key=lambda a: (
            set(a).issubset(printable_set),            # lower priority of strings that aren't printable 
            len([i for i in a if i in punctuation_set]),  # lower priority of strings with lots of punctuation
            contains_path_markers(a),  # lower priority of strings that are file paths. 
        ))
        return possible_function_names[0]
    
    def get_pcode_for_function(self, func):
        if isinstance(func, str):
            func = [i for i in self.fm.getFunctions(1) if i.getName() == func][0]
        hf = self.get_high_function(func)
        return list(hf.getPcodeOps())


def contains_path_markers(s):
    return s.find("\\") != -1 or s.find("/") != -1


def walk_pcode_until_handlable_op(varnode, maxcount=20):
    param_def = varnode.getDef()
    # handling much more than a PTRSUB or COPY will likely require an actually intelligent traversal
    # of the pcode ast, if not emulation, as registers are assigned different types
    while param_def.opcode not in [PcodeOpAST.PTRSUB, PcodeOpAST.COPY] and maxcount > 0:
        if param_def.opcode == PcodeOpAST.CAST:
            varnode = param_def.getInput(0)    
        else:
            varnode = param_def.getInput(1)
        param_def = varnode.getDef()
        maxcount -= 1

    return param_def


def main():
    fr = FunctionRenamer(currentProgram)
    funcname = askString("Which function's calls are you targeting? ", "")
    prompt = "Which parameter of %s? Please note that the argument types must be set correctly for this parameter" % funcname
    int1 = askInt(prompt, "enter parameter number")
    func = [i for i in fr.fm.getFunctions(1) if i.name == funcname][0]
    fr.rename_functions_by_function_call(func, int1)


# from name_functions_from_called_function import *
# fr = FunctionRenamer(currentProgram)

if __name__ == "__main__":
    main()