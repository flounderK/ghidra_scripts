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


class FunctionArgumentAnalyzer:
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
        self.dropped_data_refs = []
        self.dropped_callind_ops = []

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
        """
        Iterate over all of the references to an address and pick out the ones
        that can be associated with a call to the provided address
        """
        # location = get_location(func)
        # references = list(ReferenceUtils.getReferenceAddresses(location, self._monitor))
        log.info("[+] Finding callsites for %s", str(address))
        references = self.refman.getReferencesTo(address)
        incoming_calls = []
        for ref in references:
            from_address = ref.getFromAddress()
            if ref.referenceType == RefType.DATA:
                self.dropped_data_refs.append(ref)
                log.warning("[-] Dropping a DATA ref at %s", str(from_address))
                continue
            elif ref.referenceType == RefType.EXTERNAL_REF:
                continue
            elif ref.referenceType == FlowType.COMPUTED_CALL:
                # FIXME: this potentially introduces duplication of some work here
                incoming_calls.extend(self.get_callsites_for_address(from_address))
                continue

            callerFunction = self.fm.getFunctionContaining(from_address)
            if callerFunction is None:
                log.warning("[-] Drop ref %s at %s" % (str(ref.referenceType),
                                                       str(from_address)))
                continue
            incoming_calls.append(IncomingCallNode(callerFunction, from_address))
        log.info("[+] Found %d callsites", len(incoming_calls))
        return incoming_calls

    def get_pcode_ops_calling_func(self, func):
        """
        Get all of the pcode ops that call the function @func
        """
        incoming_calls = self.get_callsites_for_address(func.getEntryPoint())
        additional_analysis_needed_funcs = set()
        incoming_functions = set([i.function for i in incoming_calls])
        func_name = func.getName()

        call_ops = []
        # iterate over functions that call the passed in function
        for calling_func_node in incoming_functions:
            current_function_name = calling_func_node.getName()
            log.info("[+] Identifying call ops in %s", str(current_function_name))
            hf = self.get_high_function(calling_func_node)
            pcode_ops = list(hf.getPcodeOps())
            func_address = func.getEntryPoint()

            for op in pcode_ops:
                if op.opcode == PcodeOpAST.CALLIND:
                    log.warning("[*] skipping a CALLIND at %s", str(op.seqnum.target))
                    self.dropped_callind_ops.append(op)
                    continue
                if op.opcode != PcodeOpAST.CALL:
                    continue

                # First input of CALL op is the address being called
                called_func_address = op.getInput(0).getAddress()
                called_func = getFunctionContaining(called_func_address)
                if called_func is None:
                    log.warning("[-] A CALL op is calling into an undefined function (%s) from (%s)",
                                str(called_func_address), str(op.seqnum.target))
                    continue

                # allow a little wiggle room for thunks by allowing a match by name too
                if called_func_address != func_address and called_func.getName() != func_name:
                    continue
                call_ops.append(op)


            # call_ops = [i for i in pcode_ops if i.opcode == PcodeOpAST.CALL and i.getInput(0).getAddress() == func_address]
            if len(call_ops) == 0:
                # if no call was found, it was an indirect reference
                log.warning("[-] No call found for %s" % current_function_name)
                continue
        return call_ops

    def get_pcode_calling_ops_by_func_name(self, name):
        """
        Get all of the pcode ops that specify a call to functions named @name
        """
        call_ops = []
        for func in self.get_funcs_by_name(name):
            call_ops.extend(self.get_pcode_ops_calling_func(func))
        return list(set(call_ops))

    def get_backslice_ops_for_param_ind(self, call_op, param_ind):
        param_def = None
        param_varnode = call_op.getInput(param_index+1)
        backslice_ops = []
        if param_varnode is None:
            return backslice_ops

        backslice_ops = DecompilerUtils.getBackwardSliceToPCodeOps(param_varnode)
        if backslice_ops is None:
            return []
        # backslice_map[call_op.seqnum.target] = list(backslice_ops)
        return list(backslice_ops)


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
                maxsize -= 1
                continue

            return decoded_extracted_string

        return ""

    def is_const_pcode_op(self, op):
        """
        Check to see if all of the inputs for an operation are constants
        """
        return any([vn for vn in op.getInputs() if not vn.isConstant()])


    # def is_complex_param_source(self, ):

    def resolve_pcode_call_parameter_varnode(self, call_op, param_index):
        raise NotImplementedError("Not fully implemented")
        param_varnode = call_op.getInput(param_index+1)
        if param_varnode is None:
            return
        backslice_ops = DecompilerUtils.getBackwardSliceToPCodeOps(param_varnode)
        if backslice_ops is None:
            backslice_ops = []

        backslice_ops = list(backslice_ops)
        # check for empty list
        if not backslice_ops:
            # this means that there was a varnode created, it just wasn't
            # used in any ops. Happens with unmodified params
            # and const params (at least on i386)
            backslice = DecompilerUtils.getBackwardSlice(param_varnode)
            # FIXME: actually need to try to identify which varnode it is
            return backslice[0]


        # TODO: actually resolve the varnode
        return

    def get_pcode_for_function(self, func):
        """
        Get Pcode ops for the function @func
        """
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
        NOTE: Currently unused
        An initial attempt at a custom backslice that uses the stackspace of
        a function to identify sources and sinks for varnodes.
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

    def get_funcs_by_name(self, name):
        return [i for i in self.fm.getFunctions(1) if i.name == name]

    def has_complex_backslice(self, varnode):
        """
        Try to determine whether or not the backslice for the given varnode
        is complex or not. Complex is arbitrarily defined as "whether or not
        this code can figure out all of the possible values for it"
        """
        # a constant varnode should always be simple
        if varnode.isConstant():
            return False

        backslice = DecompilerUtils.getBackwardSlice(varnode)
        if backslice is None:
            backslice = []

        backslice = list(backslice)
        # check for empty list
        if not backslice:
            log.error("[!] There were no varnodes found for a backwards slice")
            return True

        # TODO: There are definitely other things that can't be resolved
        for vn in backslice:
            if vn.isRegister():
                return True

        return False

    def filter_calls_with_simple_param(self, call_ops, param_index):
        """
        Given a list of call_ops for a function, return the ones that
        have a sufficiently complex-enough backslice
        """
        filtered_ops = []
        for op in call_ops:
            varnode = op.getInput(param_index+1)
            if not self.has_complex_backslice(varnode):
                continue
            filtered_ops.append(op)
        return filtered_ops


def walk_pcode_until_handlable_op(varnode, maxcount=20):
    """
    Naiive Backslice-like func that follows varnode definitions
    until a knows op is found
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


