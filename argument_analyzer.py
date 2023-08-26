# analyze arguments of function calls
#@author Clifton Wolfe


from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.program.util import FunctionSignatureFieldLocation
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.symbol import FlowType, RefType
from ghidra.app.decompiler.component import DecompilerUtils
from collections import namedtuple
import string
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)

from __main__ import *


IncomingCallNode = namedtuple("IncomingCallNode", ["function", "call_address"])


def get_location(func):
    return FunctionSignatureFieldLocation(func.getProgram(),
                                          func.getEntryPoint())


class FunctionRenamer:
    def __init__(self, currentProgram):
        self.fm = currentProgram.getFunctionManager()
        self.dtm = currentProgram.getDataTypeManager()
        self.addr_fact = currentProgram.getAddressFactory()
        self.addr_space = self.addr_fact.getDefaultAddressSpace()
        self.mem = currentProgram.getMemory()
        self.sym_tab = currentProgram.getSymbolTable()
        # NOTE: A better way to find this register needs to be found
        # if it is even still needed
        # self._stack_reg_offset = currentProgram.getRegister("sp").getOffset()

        self.ptr_size = self.addr_space.getPointerSize()
        if self.ptr_size == 4:
            self._get_ptr_size = self.mem.getInt
        elif self.ptr_size == 8:
            self._get_ptr_size = self.mem.getLong

        self._null = self.addr_space.getAddress(0)
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

    def get_callsites_for_address(self, address):
        # location = get_location(func)
        # references = list(ReferenceUtils.getReferenceAddresses(location, self._monitor))
        references = self.refman.getReferencesTo(address)
        incoming_calls = []
        for ref in references:
            # self._monitor.checkCanceled()
            from_address = ref.getFromAddress()
            # TODO: This doesn't handle CALCULATED_CALLs, or DATA/EXTERNAL
            # TODO: refs, which include thunks and vtables/embedded func ptrs
            callerFunction = self.fm.getFunctionContaining(from_address)
            if callerFunction is None:
                log.warning("Drop ref %s at %s" % (str(ref.referenceType),
                                                   str(from_address)))
                continue
            incoming_calls.append(IncomingCallNode(callerFunction, call_address))
        return incoming_calls

    def backslice_for_func_arg(self, func, param_index):
        incoming_calls = self.get_callsites_for_address(func.getEntryPoint())
        additional_analysis_needed_funcs = set()
        incoming_functions = set([i.function for i in incoming_calls])
        backslice_map = {}
        for calling_func_node in incoming_functions:
            current_function_name = calling_func_node.getName()
            # calling_func_node = incoming_calls[1]
            hf = self.get_high_function(calling_func_node)
            pcode_ops = list(hf.getPcodeOps())
            func_address = func.getEntryPoint()

            # TODO: rework call_ops filter to accept things of the same name
            call_ops = [i for i in pcode_ops if i.opcode == PcodeOpAST.CALL and i.getInput(0).getAddress() == func_address]
            if len(call_ops) == 0:
                log.warning("no call found for %s" % current_function_name)
                continue

            copied_values = []
            param_def = None
            for call_op in call_ops:
                param_varnode = call_op.getInput(param_index+1)
                if param_varnode is None:
                    continue

                backslice_ops = DecompilerUtils.getBackwardSliceToPCodeOps(param_varnode)
                if backslice_ops is None:
                    continue
                backslice_map[call_op.seqnum.target] = list(backslice_ops)

        return backslice_map


    def read_string_at(self, address, maxsize=256):
        """
        Tries to extract strings from a binary
        """
        while maxsize > 0:
            # This is supposed to handle the case of a string being very
            # close to the end of a memory region and the maxsize being larger
            # than the remainder
            try:
                string_bytearray = bytearray(getBytes(address, maxsize))
            except:
                maxsize -= 1
                continue

            terminator_index = string_bytearray.find(b'\x00')
            extracted_string_bytes = string_bytearray[:terminator_index]
            try:
                decoded_extracted_string = extracted_string_bytes.decode()
            except:
                log.warning("Unable to decode as string")
                break
            return decoded_extracted_string

        return ""

    def get_pcode_for_function(self, func):
        hf = self.get_high_function(func)
        return list(hf.getPcodeOps())

    def get_data_accesses_from_function(self, func):
        pcode_ops = self.get_pcode_for_function(func)
        stackspace_id = self.addr_fact.getStackSpace().spaceID
        varnodes = set(sum([[op.getOutput()] + list(op.getInputs()) for op in pcode_ops], []))
        # filter out the majority of nodes that are known to be out
        varnodes = [i for i in varnodes if i is not None and i.getSpace() != stackspace_id]
        # get all of the offsets that are within current addressSpace
        valid_data_addresses = []
        for node in varnodes:
            addr = self.addr_space.getAddress(node.getOffset())
            if self.mem.contains(addr):
                valid_data_addresses.append(addr)
        return valid_data_addresses

    def get_pcode_op_copy_operand(self, pcode_ops, ptrsub_op):
        """
        Somewhat naive backslice
        """
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


def walk_pcode_until_handlable_op(varnode, maxcount=20):
    """
    Backslice only handling pcode PTRSUB and COPY
    """
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


# from function_renamer import *
# fr = FunctionRenamer(currentProgram)