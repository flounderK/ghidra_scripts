
from __main__ import *
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils



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

