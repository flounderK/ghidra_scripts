from ghidra.program.model.pcode import PcodeOpAST, VarnodeAST
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript
from ghidra.program.util import FunctionSignatureFieldLocation
from ghidra.program.model.symbol import FlowType, RefType, SourceType
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.data import MetaDataType
from ghidra.program.model.data import DefaultDataType

import logging
from decomp_utils import DecompUtils
from function_signature_utils import set_param_datatype, set_num_params, getDataTypeForParam
from datatype_utils import getVoidPointerDatatype, areBaseDataTypesEquallyUnique

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)

from __main__ import *


class FunctionCallArgContext(object):
    """
    A class representing the arguments for a call to a specific address
    """
    def __init__(self, to_address=None):
        self.args = {}
        self.to_address = to_address
        self.called_to_func = None
        self._to_repr = "TO"
        if to_address is not None:
            self._to_repr = str(to_address)
            self.called_to_func = getFunctionContaining(to_address)
            if self.called_to_func is not None:
                self._to_repr = self.called_to_func.name

    def add_arg(self, arg, arg_num):
        """
        Arg num is indexed from 1 to preserve
        consistency with pcode call ops.
        arg_num is not equivalent to slot
        """
        self.args[arg_num] = arg

    def merge(self, other):
        for k, v in other.args.items():
            existing = self.args.get(k)
            if existing is None:
                self.args[k] = v

    def __repr__(self):
        return "%s(%s)" % (self._to_repr,
                           ", ".join(["%d" % i for i in self.args.keys()]))


class FunctionArgContextCollection(object):
    """
    A class representing a related collection of FunctionCallArgContext. These
    FunctionCallArgContexts do not have to be from the same function.
    """
    def __init__(self):
        self.function_call_args = {}

    def add(self, arg_ctx, merge=True):
        """
        FunctionCallArgContext
        """
        key = arg_ctx.to_address
        if merge is True:
            existing = self.function_call_args.get(key)
            if existing is not None:
                existing.merge(arg_ctx)
                arg_ctx = existing
        self.function_call_args[key] = arg_ctx

    def get(self, called_addr):
        """
        Get a FunctionCallArgContext for the specified address
        """
        key = called_addr
        maybe_v = self.function_call_args.get(key)
        if maybe_v is None:
            maybe_v = FunctionCallArgContext(called_addr)
            self.function_call_args[key] = maybe_v
        return maybe_v


def trace_struct_fwd_to_call(varnodes, func_arg_holder=None, allow_ptrsub_zero=False):
    """
    Within a single function, trace the specified varnodes forward to any call operations.
    Does not follow through dereferences
    """
    def _add_to_list(curr_vn, vn_cand, to_visit, visited):
        if vn_cand is None:
            return
        if vn_cand in visited:
            return
        if vn_cand in to_visit:
            return
        if vn_cand == curr_vn:
            return
        to_visit.append(vn_cand)

    if func_arg_holder is None:
        func_arg_holder = FunctionArgContextCollection()

    refman = currentProgram.getReferenceManager()
    if not hasattr(varnodes, '__iter__'):
        varnodes = [varnodes]

    to_visit = list(varnodes)
    visited = set()
    while to_visit:
        vn = to_visit.pop()
        desc_ops = vn.getDescendants()
        for op in desc_ops:
            opcode = op.opcode
            if opcode in [PcodeOpAST.CALL, PcodeOpAST.CALLIND]:
                inputs = list(op.getInputs())
                call_addr = op.getSeqnum().getTarget()
                for ref in refman.getReferencesFrom(call_addr):
                    if ref.referenceType.isCall() is False:
                        continue
                    func_call_args = func_arg_holder.get(ref.toAddress)
                    for i in range(1, len(inputs)):
                        if inputs[i] != vn:
                            continue
                        # TODO: use data type here
                        func_call_args.add_arg(i, i)

            elif opcode in [PcodeOpAST.COPY, PcodeOpAST.CAST,
                            PcodeOpAST.MULTIEQUAL, PcodeOpAST.PIECE,
                            PcodeOpAST.SUBPIECE]:
                # basically just ops where the decompiler could
                # change the type or size of the vn. decompiler
                # will generate these if a parameter for a call
                # is set to the incorrect type or size
                vn_cand = op.getOutput()
                _add_to_list(vn, vn_cand, to_visit, visited)
            elif opcode == PcodeOpAST.PTRSUB and allow_ptrsub_zero is True:
                # an optimization to make the decompiler output look
                # closer to C code can add in a dummy ptrsub vn, 0
                # to allow passing field0_0x0 into function calls
                offset_vn = op.getInput(1)
                if not offset_vn.isConstant():
                    log.error("PTRSUB offset was non-const %s %s" %
                              (str(op.getSeqnum().getTarget()),
                               str(op)))
                    continue
                offset = int(offset_vn.getOffset())
                # this is probably not a real access to a field,
                # the edge case this is looking for
                if offset == 0:
                    vn_cand = op.getOutput()
                    _add_to_list(vn, vn_cand, to_visit, visited)
                # TODO: maybe handle multi-level propagation
            elif opcode == PcodeOpAST.PTRADD:
                # TODO: confirm that PTRADD can not occur for passing
                # TODO: a pointer on [0] if a structure datatype is
                # TODO: confused with an array

                # TODO: maybe handle multi-level propagation
                pass
            elif opcode in [PcodeOpAST.INT_ADD, PcodeOpAST.INT_SUB]:
                # even though it doesn't make sense for correctly typed
                # things, an ADD or SUB would be seen in situations
                # where the type of a struct ptr is is incorrect
                vn_cand = op.getOutput()
                _add_to_list(vn, vn_cand, to_visit, visited)
            elif opcode in [PcodeOpAST.STORE, PcodeOpAST.LOAD]:
                # If load or store is handled then the traced
                # value would be a different value or type
                continue
        visited.add(vn)
    return func_arg_holder


def trace_struct_forward(varnodes, allow_ptrsub_zero=False):
    """
    Trace forward from a varnode or varnodes to all locations in this
    function and in functions called by this function and identify if the
    specified varnodes are passed directly into other functions
    returns a FunctionArgContextCollection. This effectively traces places where
    a struct pointer is passed as an argument
    """
    if not hasattr(varnodes, '__iter__'):
        varnodes = [varnodes]
    du = DecompUtils()
    func_arg_holder = FunctionArgContextCollection()
    # get the top level of FunctionCallArgContext
    trace_struct_fwd_to_call(varnodes, func_arg_holder, allow_ptrsub_zero=allow_ptrsub_zero)
    to_visit = set([i for i in func_arg_holder.function_call_args.values()])
    visited = set()
    visited_to_addrs = set()
    while to_visit:
        curr_arg_ctx = to_visit.pop()
        curr_func = curr_arg_ctx.called_to_func
        if curr_func is None:
            log.error("Have to skip %s because no to func could be identified" % str(curr_arg_ctx))
            continue
        in_vns = []
        was_error = False
        for param_num, v in curr_arg_ctx.args.items():
            maybe_vns = du.get_varnodes_for_param(curr_func, param_num)
            if maybe_vns is None:
                was_error = True
                break
            in_vns += maybe_vns
        if was_error is True:
            # without tracking to_addresses separately this search will
            # check many many call edges, even if the called function has
            # already been checked before
            log.error("couldn't get varnodes for %s" % (curr_func.name))
            visited_to_addrs.add(curr_arg_ctx.to_address)
            continue
        tmp_arg_holder = trace_struct_fwd_to_call(in_vns, allow_ptrsub_zero=allow_ptrsub_zero)
        for cand_arg_ctx in tmp_arg_holder.function_call_args.values():
            if cand_arg_ctx in visited:
                continue
            if cand_arg_ctx in to_visit:
                continue
            if cand_arg_ctx.to_address in visited_to_addrs:
                continue
            if cand_arg_ctx == curr_arg_ctx:
                continue
            to_visit.add(cand_arg_ctx)
        visited.add(curr_arg_ctx)
        visited_to_addrs.add(curr_arg_ctx.to_address)

    for arg_ctx in visited:
        func_arg_holder.add(arg_ctx)
    return func_arg_holder


def propagate_datatype_forward_to_function_signatures(varnodes, datatype, program=None, skip_external=True, overwrite_voidp=False, prefer_existing=True, force_new=False, undef_only=True):
    """
    Propagate a datatype forward to all function signatures the specified varnodes are passed to
    """
    if program is None:
        program = currentProgram
    func_arg_ctx_collection = trace_struct_forward(varnodes)
    voidp_dt = getVoidPointerDatatype(program)

    for addr, arg_ctx in func_arg_ctx_collection.function_call_args.items():
        if arg_ctx.to_address is None:
            log.info("skipping a reference to an unknown function call because there is no `to` address")
            continue
        if arg_ctx.called_to_func is None:
            log.warning("skipping a reference to %s because there is no function defined there" % str(arg_ctx.to_address))
            continue
        # resolve thunk if necessary
        func = arg_ctx.called_to_func
        if func.isThunk():
            func = func.getThunkedFunction(1)
        # changing types on externals can cause some issues, so avoid it by default
        if func.isExternal() and skip_external is True:
            continue
        for param_num, param_v in arg_ctx.args.items():
            existing_datatype = getDataTypeForParam(func, param_num)
            if existing_datatype is None:
                log.warning("existing datatype was None for %s param %d. Running Decompiler Parameter ID analysis may resolve this." % (func.name, param_num))
                existing_datatype = DefaultDataType()
            if existing_datatype == voidp_dt and overwrite_voidp is False:
                # don't overwrite void* because of functions like memcpy that actually use that type
                continue
            if existing_datatype == datatype:
                # if the parameter's datatype is already this datatype, we aren't making a change and shouldn't
                # do anything
                continue
            if undef_only is True and not existing_datatype.name.startswith("undefined"):
                continue
            if force_new is False:
                # getMostSpecificDataType prefers the first argument if the datatypes are equally specific
                if prefer_existing is True:
                    preferred_dt, less_preferred_dt = existing_datatype, datatype
                else:
                    preferred_dt, less_preferred_dt = datatype, existing_datatype
                chosen_datatype = MetaDataType.getMostSpecificDataType(preferred_dt, less_preferred_dt)
                if chosen_datatype != datatype:
                    log.warning("skipping %s because the more specific datatype is not the provided one. to ignore this, run the function with force_new=True" % func.name)
                    continue
            set_param_datatype(func, param_num, datatype, program)
            func.addTag("AUTO_PROPAGATED_PARAM_%d_DATATYPE" % param_num)
