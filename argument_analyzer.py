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
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.listing import ReturnParameterImpl
from ghidra.program.model.listing import ParameterImpl
# eventually would like to use this
# from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from collections import namedtuple
import string
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)

from __main__ import *


IncomingCallNode = namedtuple("IncomingCallNode", ["function", "call_address"])


class FunctionArgumentAnalyzer:
    def __init__(self, currentProgram):
        self.fm = currentProgram.getFunctionManager()
        self.dtm = currentProgram.getDataTypeManager()
        self.addr_fact = currentProgram.getAddressFactory()
        self.addr_space = self.addr_fact.getDefaultAddressSpace()
        self.mem = currentProgram.getMemory()
        self.sym_tab = currentProgram.getSymbolTable()

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
            if hf is None:
                log.warning("[-] Failed to get a High function, unable to decompile")
                continue
            pcode_ops = list(hf.getPcodeOps())
            func_address = func.getEntryPoint()

            for op in pcode_ops:
                if op.opcode == PcodeOpAST.CALLIND:
                    # log.warning("[*] skipping a CALLIND at %s", str(op.seqnum.target))
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

    def _get_pcode_op_copy_operand(self, pcode_ops, ptrsub_op):
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


        for vn in backslice:
            # FIXME: This check is insufficient
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

    def get_descendant_called_funcs(self, func):
        """
        Attempt to get every function that the specified function @func
        calls both directly and indirectly
        """
        visited_functions = set()
        to_visit_stack = set([func])
        call_ops_set = set([PcodeOpAST.CALLIND, PcodeOpAST.CALL])
        while to_visit_stack:
            fun = to_visit_stack.pop()
            # immediately add it to visited so that it
            # can't be processed twice
            visited_functions.add(fun)
            pcode_ops = self.get_pcode_for_function(fun)
            call_ops = [i for i in pcode_ops if i.opcode in call_ops_set]
            for op in call_ops:
                if op.opcode == PcodeOpAST.CALLIND:
                    # TODO: handle callinds
                    continue
                if op.opcode != PcodeOpAST.CALL:
                    raise NotImplementedError("Unhandled opcode encountered")

                # inp 0 is called addr
                called_addr = op.getInput(0).getAddress()
                called_func = getFunctionContaining(called_addr)
                if called_func is None:
                    log.warning("Call to unknown function %s -> %s",
                                op.seqnum.target,
                                called_addr)
                    continue
                if called_func not in visited_functions:
                    to_visit_stack.add(called_func)
        return list(visited_functions)

    def get_called_funcs_with_param_as_argument(self, func, param_ind):
        """
        Identify any function calls in the specified function @func that
        take the parameter at @param_ind (or an equivalent) as a parameter.
        """

        high_func = self.get_high_function(func)
        proto = high_func.getFunctionPrototype()
        num_params = proto.getNumParams()
        param_high_sym = proto.getParam(param_ind)
        high_var = param_high_sym.getHighVariable()
        param_varnodes = set(high_var.getInstances())
        pcode_ops = self.get_pcode_for_function(func)

        # TODO: this might be best as its own function
        # collect all of the varnodes that are the param or a direct
        # cast/copy of it
        added_varnode = True
        while added_varnode is True:
            added_varnode = False
            for op in pcode_ops:
                if op.opcode not in [PcodeOpAST.CAST, PcodeOpAST.COPY]:
                    continue
                # only one input possible
                inp = op.getInput(0)
                outp = op.getOutput()
                if inp in param_varnodes and outp not in param_varnodes:
                    param_varnodes.add(outp)
                    added_varnodes = True
                    # don't break here so that all of the ops before this
                    # in the list don't have to be re-checked until
                    # the next pass

        functions_taking_param_as_argument = set()
        for op in pcode_ops:
            # TODO: probably need to handle CALLIND here
            if op.opcode != PcodeOpAST.CALL:
                continue
            inputs_raw = list(op.getInputs())
            called_addr_varnode = inputs_raw[0]
            # skip the first input because it is the call address
            inputs = inputs_raw[1:]

            # TODO: determine if this actually saves any time
            # filter out call ops that don't have a param varnode
            input_set = set(inputs)
            if not param_varnodes.intersection(input_set):
                continue

            for ind, param_inp in enumerate(inputs):
                if param_inp not in param_varnodes:
                    continue

                called_func = getFunctionContaining(called_addr_varnode.getAddress())
                if called_func is None:
                    log.warning("Calling a function that isn't defined")
                    continue
                functions_taking_param_as_argument.add((called_func, ind))
        return list(functions_taking_param_as_argument)

    def realize_func_sig_from_op(self, call_op):
        """
        Initial attempt
        @call_op PcodeOpAST CALL op
        compare the number of arguments between a decompiled
        function and the function before decompilation.
        This is kind of a discount ApplyFunctionSignatureCmd
        """

        if call_op.opcode != PcodeOpAST.CALL:
            return

        func_addr = call_op.getInput(0).getAddress()
        func = getFunctionContaining(func_addr)
        if func is None:
            log.warning("Call to non-existant function %s -> %s",
                        call_op.seqnum.target,
                        func_addr)
            return
        log.info("Propagating arguments for %s", func.getName())

        # remove one input for called address
        op_arg_count = call_op.getNumInputs() - 1
        expected_param_count = func.getParameterCount()
        high_func = self.get_high_function(func)
        proto = high_func.getFunctionPrototype()
        proto_param_count = proto.getNumParams()
        # TODO: handle return type differences
        needs_return_fixup = False
        if func.returnType != proto.returnType:
            needs_return_fixup = True

        if expected_param_count >= proto_param_count:
            return
        log.info("expected param %d proto param %d",
                 expected_param_count,
                 proto_param_count)

        # TODO: handle additional arguments passed into the call
        # TODO: in the call_op
        num_params_to_use = proto_param_count

        params = []
        for i in range(proto_param_count):
            high_sym = proto.getParam(i)
            # TODO: maybe save comments too
            param_def = ParameterImpl(
                            high_sym.getName(),
                            high_sym.getDataType(),
                            currentProgram)
            params.append(param_def)

        # TODO: dynamically choose return type
        return_param = ReturnParameterImpl(proto.getReturnType(),
                                           currentProgram)
        func.updateFunction(func.callingConventionName,
                            return_param, params,
                FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                            False, SourceType.USER_DEFINED)


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


