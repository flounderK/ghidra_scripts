
from __main__ import *
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)


class DecompUtils:
    """
    Utilities on top of the existing decompiler utils
    """
    def __init__(self, program=None, monitor_inst=None, decomp_timeout=60):
        if program is not None:
            self.program = program
        else:
            self.program = currentProgram
        self.addr_fact = self.program.getAddressFactory()
        self.dtm = self.program.getDataTypeManager()
        self._decomp_options = DecompileOptions()
        if monitor_inst is None:
            self._monitor = monitor
        else:
            self._monitor = monitor_inst
        self._ifc = DecompInterface()
        self._ifc.setOptions(self._decomp_options)
        self.fm = self.program.getFunctionManager()
        self.decomp_timeout = decomp_timeout

    def get_funcs_by_name(self, name):
        """
        Get all of the functions that match the name @name
        """
        return [i for i in self.fm.getFunctions(1) if i.name == name]

    def get_high_function(self, func, timeout=None):
        """
        Get a HighFunction for a given function
        """
        res = self.get_decompiler_result(func, timeout)
        high_func = res.getHighFunction()
        return high_func

    def get_decompiler_result(self, func, timeout=None):
        """
        Get decompiler results for a given function
        """
        if timeout is None:
            timeout = self.decomp_timeout
        self._ifc.openProgram(func.getProgram())
        res = self._ifc.decompileFunction(func, timeout, self._monitor)
        return res

    def get_function_prototype(self, func, **kwargs):
        """
        Get the function prototype for function @func
        """
        hf = self.get_high_function(func, **kwargs)
        if hf is None:
            return None
        return hf.getFunctionPrototype()

    def _get_high_sym_for_param_by_index(self, func, index, **kwargs):
        """
        Get the HighSymbol for a function's parameter. Parameter is specified
        by @index, and indexes start at zero. @index will NOT match up
        with the parameter numbers from the decompiler window
        """
        proto = self.get_function_prototype(func, **kwargs)
        if proto is None:
            log.warning("No prototype for %s" % func.name)
            return None
        num_params = proto.getNumParams()
        if num_params-1 < index:
            log.warning("Parameter index %d does not exist in %s which has %d parameters" % (index, func.name, num_params))
            return None
        high_sym = proto.getParam(index)
        return high_sym

    def get_high_sym_for_param(self, func, param_num, **kwargs):
        """
        Get the HighSymbol for a function. @param_num matches up with parameter
        numbers visible in the decompiler window
        """
        return self._get_high_sym_for_param_by_index(func, param_num-1, **kwargs)


    def get_varnodes_for_param(self, func, param_num, **kwargs):
        """
        Gets the varnodes for a function parameter. @param_num matches up with
        the parameter number from the decompiler window
        """
        high_sym = self.get_high_sym_for_param(func, param_num, **kwargs)
        if high_sym is None:
            log.warning("No HighSymbol for %s param %d " % (func.name, param_num))
            return None
        # it is actually legitimate for there to be no high variable or
        # varnodes for a high symbol, like in cases where the parameter is just
        # unused
        high_var = high_sym.getHighVariable()
        if high_var is None:
            # log.warning("No HighVariable for %s param %d " % (func.name, param_num))
            return []
        vn_arr = high_var.getInstances()
        if vn_arr is None:
            # log.warning("No Varnode instances for %s param %d " % (func.name, param_num))
            return []
        return list(vn_arr)

    def get_all_parameter_varnodes(self, func, **kwargs):
        """
        Get a list of lists of varnodes for all paramters to @func
        """
        proto = self.get_function_prototype(func, **kwargs)
        if proto is None:
            log.warning("No prototype for %s" % func.name)
            return None
        num_params = proto.getNumParams()
        if num_params == 0:
            return []
        varnodes_lists = []
        for param_num in range(1, num_params+1):
            vns = self.get_varnodes_for_param(func, param_num, **kwargs)
            if vns is None:
                log.error("unable to get varnodes for param %d" % param_num)
                continue
            varnodes_lists.append(vns)
        return varnodes_lists

    def get_pcode_for_function(self, func, **kwargs):
        """
        Get an unsorted list of PcodeOps for the function @func
        """
        hf = self.get_high_function(func, **kwargs)
        if hf is None:
            log.warning("couldn't get high function for %s" % func.name)
            return None
        return list(hf.getPcodeOps())

    def varnode_is_direct_source_of(self, source_vn_cand, descendant_vn_cand):
        """
        Check to see if the Varnode @source_vn_cand directly leads to
        @descendant_vn_cand
        """
        if source_vn_cand == descendant_vn_cand:
            return True
        defining_op = descendant_vn_cand.getDef()
        # an op with no definition is likely a parameter, global,
        # uninitialized, or part of a composite struct on the stack or in ram
        # that hasn't been recovered
        if defining_op is None:
            return False
        fwd_slice_vns = list(DecompilerUtils.getForwardSlice(source_vn_cand))
        # TODO: check to see if anything else weird could happen to make this
        # TODO: not handle all cases
        if descendant_vn_cand in source_vn_cand:
            return True
        return False

    def varnode_leads_to_definition_of(self, source_vn_cand, descendant_vn_cand):
        """
        Check to see if the Varnode @source_vn_cand directly leads to
        inputs to the defining op of @descendant_vn_cand
        """
        if source_vn_cand == descendant_vn_cand:
            return True
        defining_op = descendant_vn_cand.getDef()
        # an op with no definition is likely a parameter, global,
        # uninitialized, or part of a composite struct on the stack or in ram
        # that hasn't been recovered
        if defining_op is None:
            return False
        defining_op_inputs = list(defining_op.getInputs())
        defining_op_inputs_set = set(defining_op_inputs)

        fwd_slice_vns = list(DecompilerUtils.getForwardSlice(source_vn_cand))
        fwd_slice_vns_set = set(fwd_slice_vns)
        intersecting_vns = fwd_slice_vns_set.intersection(defining_op_inputs_set)
        if len(intersecting_vns) > 0:
            return True
        return False


