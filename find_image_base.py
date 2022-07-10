# Idempotent script to try to find the base and regions
# of firmware images
#
#@author Clifton Wolfe
#@category C++

from collections import defaultdict
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript
from ghidra.app.util import MemoryBlockUtils
from ghidra.program.model.address import AddressSet
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.program.model.address import GenericAddress, Address
from ghidra.program.model.symbol import FlowType
import sys


class DisassemblyHelper:
    def __init__(self, currentProgram):
        self.fm = currentProgram.getFunctionManager()
        self.dtm = currentProgram.getDataTypeManager()
        self.addr_fact = currentProgram.getAddressFactory()
        self.default_addr_space = self.addr_fact.getDefaultAddressSpace()
        self.mem = currentProgram.getMemory()
        self.sym_tab = currentProgram.getSymbolTable()

        self.ptr_size = self.default_addr_space.getPointerSize()
        if self.ptr_size == 4:
            self._get_ptr_size = self.mem.getInt
        elif self.ptr_size == 8:
            self._get_ptr_size = self.mem.getLong

        self._null = self.default_addr_space.getAddress(0)
        self._decomp_options = DecompileOptions()
        self._monitor = ConsoleTaskMonitor()
        self._ifc = DecompInterface()
        self._ifc.setOptions(self._decomp_options)

    def get_high_function(self, func, timeout=60):
        """
        Get a HighFunction for a given function
        """
        self._ifc.openProgram(func.getProgram())
        res = self._ifc.decompileFunction(func, timeout, self._monitor)
        high_func = res.getHighFunction()
        return high_func

    def get_pcode_ops_for_func(self, func):
        """
        Get a list of the PCODE ops for a function
        """
        hf = self.get_high_function(func)
        if hf is None:
            return []
        return hf.getPcodeOps()

# TODO: RegionFinder
# Track non-stack accesses/calls in rom to addresses that aren't mapped,
# identify minimums and maximums.
# group the accesses by page,
#
#
# Identifying possible base address
# While invalid memory accesses could indicate either the expected load
# address of the binary or the address of mmio/ something else,
# invalid call addresses indicate executable memory. Executable memory
# cannot be uninitialized and work as intended, so one of the following
# is likely expected to be in that location:
#  - this binary (or an in memory copy of it), at a different
#        base address. This might be the case if the binary
#        isn't PIE or has an entirely separate copy of itself
#        for a data segment
#  - a separate, uknown binary, like something placed into memory by
#        a different chip
#  - something like JIT code/self modifying code, placed there at
#        runtime
#
# This inference can be used as a data point and an attempt can be made
# to identify if the called addresses actually correctly look like they
# could be calls to this binary, just in a different location in memory
#
#


class MemoryRegionFinder:
    def __init__(self, currentProgram, page_size=0x1000,
                 error_thresh_pages=8):
        self.currentProgram = currentProgram
        self.dh = DisassemblyHelper(currentProgram)
        self.page_size = page_size
        # TODO: make sure jython doesn't mess with this like it
        # does with ctypes
        self._page_mask = sys.maxsize ^ (page_size - 1)
        self._page_addrs = []
        self._invalid_calls = []
        self._invalid_accesses = []

        self._error_thres = self.page_size*error_thresh_pages
        self._find_invalid_accesses()
        self._consolidated_pages = self._get_addr_set_pages(self._invalid_accesses)

    def _find_invalid_accesses(self):
        """
        Search for referenced addresses outside of the currently
        defined memory space
        https://gist.github.com/starfleetcadet75/cdc512db77d7f1fb7ef4611c2eda69a5
        """
        listing = self.currentProgram.getListing()
        mem = self.dh.mem
        monitor = self.dh._monitor
        invalid_accesses = set()
        invalid_call_addrs = set()
        for instr in listing.getInstructions(1):
            if monitor.isCancelled():
                break
            for ref in instr.getReferencesFrom():
                to_addr = ref.getToAddress()
                if mem.contains(to_addr) or \
                   to_addr.isStackAddress() or \
                   to_addr.isRegisterAddress():
                    continue

                reftype = ref.getReferenceType()
                if reftype in [FlowType.UNCONDITIONAL_JUMP,
                               FlowType.UNCONDITIONAL_CALL]:
                    invalid_call_addrs.add(to_addr)
                else:
                    invalid_accesses.add(to_addr)

        self._invalid_calls = list(invalid_call_addrs)
        self._invalid_calls.sort()
        self._invalid_accesses = list(invalid_accesses)
        self._invalid_accesses.sort()

    def _get_addr_set_pages(self, addrs):
        """
        Consolidate the addresses in a list of addresses
        and return an address set that specifies pages instead
        of individual addresses
        Note: only uses minAddress, not maxAddress
        """
        self._page_addrs = [i.getOffset() & self._page_mask
                            for i in addrs]
        self._page_addrs = list(set(self._page_addrs))
        self._page_addrs.sort()
        if len(self._page_addrs) == 0:
            return addrs

        # #speedhack
        create_new_addr_func = self.dh.default_addr_space.getAddress
        new_addr_set = AddressSet()
        region = []
        last_addr = None
        for addr in self._page_addrs:
            if last_addr is None or \
               (last_addr + self._error_thres) >= addr:
                region.append(addr)
                last_addr = addr
                continue

            min_addr = create_new_addr_func(region[0])
            max_addr_val = region[-1] + self.page_size - 1
            max_addr = create_new_addr_func(max_addr_val)
            new_addr_set.addRange(min_addr, max_addr)
            region = []
            last_addr = None

        if region:
            min_addr = create_new_addr_func(region[0])
            max_addr_val = region[-1] + self.page_size - 1
            max_addr = create_new_addr_func(max_addr_val)
            new_addr_set.addRange(min_addr, max_addr)

        return new_addr_set


# if __name__ == '__main__':
# rbf = RomBaseFinder(currentProgram)
# from find_image_base import *
# dh = DisassemblyHelper(currentProgram)
