# The script is meant to name functions across a file based on an argument 
# passed into a called function
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
from ghidra.program.model.pcode import VarnodeAST
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil
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
        for calling_func_node in incoming_calls:
            # calling_func_node = incoming_calls[1]
            hf = self.get_high_function(calling_func_node.function)
            pcode_ops = list(hf.getPcodeOps())
            func_address = func.getEntryPoint()

            call_ops = [i for i in pcode_ops if i.opcode == PcodeOpAST.CALL and i.getInput(0).getAddress() == func_address]
            if len(call_ops) == 0:
                continue
            call_op = call_ops[0]
            param_varnode = call_op.getInput(param_index+1)
            # check here if param is just the raw address. if not...
            try:
                param_def = follow_until_ptrsub(param_varnode)
            except:
                additional_analysis_needed_funcs.add(calling_func_node.function)
            # print("param def '%s'" % str(param_def))
            # there is a weird roundabout way of looking stuff up here because there is a varnode being compared 
            # with an arbitrary stackpointer offset
            # is_stackpointer_offset = any([i for i in param_def.getInputs() if i.isRegister() and i.getOffset() == self._stack_reg_offset])
            # for whatever reason, the created varnode here gets put into unique space, not stack space, 
            copied_values = self.follow_ptrsub_ref(pcode_ops, param_def)
            possible_function_names = [self.read_string_at(i) for i in copied_values]
            best_function_name = fr.choose_best_function_name(possible_function_names)
            # print("best function name %s" % best_function_name)
            # TODO: identify whether the `SourceType` of a function's name can be accessed so that names don't get overwritten
            if best_function_name is not None and current_function_name != best_function_name and \
                current_function_name.startswith("FUN_"):  # so that other user defined function names don't get overwritten
                print("changing name from %s to %s" % (current_function_name, best_function_name))
                calling_func_node.function.setName(best_function_name, SourceType.USER_DEFINED)    

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

    def follow_ptrsub_ref(self, pcode_ops, ptrsub_op):
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


def contains_path_markers(s):
    return s.find("\\") != -1 or s.find("/") != -1

def follow_until_ptrsub(varnode):
    param_def = varnode.getDef()
    while param_def.opcode != PcodeOpAST.PTRSUB:
        varnode = param_def.getInput(1)
        param_def = varnode.getDef()
        if param_def.opcode == PcodeOpAST.MULTIEQUAL:
            print("MULTIEQUAL op found, results might be incorrect")
    return param_def






# from name_functions_from_called_function import *
from name_functions_from_called_function import FunctionRenamer
fr = FunctionRenamer(currentProgram)
# log_func = [i for i in fr.fm.getFunctions(1) if i.name == 'log_something_with_filename_and_functionname' ][0]
log_func = [i for i in fr.fm.getFunctions(1) if i.name == 'log_something_else' ][0]

incoming_calls = fr.get_callsites_for_function(log_func)
param_index = 8
additional_analysis_needed_funcs = set()
for index, calling_func_node in enumerate(incoming_calls):
    current_function_name = calling_func_node.function.getName()
    # print("looking at %s, index %d" % (current_function_name, index))
    # calling_func_node = incoming_calls[1]
    hf = fr.get_high_function(calling_func_node.function)
    pcode_ops = list(hf.getPcodeOps())
    func_address = log_func.getEntryPoint()

    call_ops = [i for i in pcode_ops if i.opcode == PcodeOpAST.CALL and i.getInput(0).getAddress() == func_address]
    if len(call_ops) == 0:
        continue
    call_op = call_ops[0]
    param_varnode = call_op.getInput(param_index+1)
    # check here if param is just the raw address. if not...
    # param_def = param_varnode.getDef()
    try:
        param_def = follow_until_ptrsub(param_varnode)
    except:
        additional_analysis_needed_funcs.add(calling_func_node.function)
        # print("\n** %s likely requires manual analysis or decompilation fixups" % current_function_name)
    # print("param def '%s'" % str(param_def))

    # there is a weird roundabout way of looking stuff up here because there is a varnode being compared 
    # with an arbitrary stackpointer offset
    is_stackpointer_offset = any([i for i in param_def.getInputs() if i.isRegister() and i.getOffset() == fr._stack_reg_offset])

    copied_values = fr.follow_ptrsub_ref(pcode_ops, param_def)
    possible_function_names = [fr.read_string_at(i) for i in copied_values]

    best_function_name = fr.choose_best_function_name(possible_function_names)
    # print("best function name %s" % str(best_function_name))
    if best_function_name is not None and current_function_name != best_function_name:
        print("changing name from %s to %s" % (current_function_name, best_function_name))
        calling_func_node.function.setName(best_function_name, SourceType.USER_DEFINED)    


for i in additional_analysis_needed_funcs:
    print("\n** %s likely requires manual analysis or decompilation fixups" % i.getName())

"""
# find the string that is being pointed to 
string_addresses = list(set([fr.addr_space.getAddress(i.getOffset()) for i in copied_values]))

function_name = fr.read_string_at(string_addresses[0])

print("changing name from %s to %s" % (calling_func_node.function.getName(), function_name))
calling_func_node.function.setName(function_name, SourceType.USER_DEFINED)
"""

# forward search
# indir = [i for i in pcode_ops if output in i.getInputs()][0]