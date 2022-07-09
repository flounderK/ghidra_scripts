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
        # pcode_ops = list(hf.getPcodeOps())
        # return pcode_ops

        # for i in pcode_ops:
        #     print(i)
        #     if i.mnemonic.find(u'BRANCH') != -1 or i.mnemonic.find(u'CALL') != -1:
        #         pcode_op = i
        #         break


# TODO: RegionFinder
# Track non-stack accesses/calls in rom to addresses that aren't mapped,
# identify minumums and maximums.
# group the accesses by page,
#

class MemoryRegionFinder:
    def __init__(self, currentProgram, page_size=0x1000, error_thresh_pages=8):
        self.currentProgram = currentProgram
        self.dh = DisassemblyHelper(currentProgram)
        self.page_size = page_size
        # TODO: make sure jython doesn't mess with this like it
        # does with ctypes
        self._page_mask = sys.maxsize ^ (page_size - 1)

        self._error_thres = self.page_size*error_thresh_pages
        addr_set = self.find_invalid_accesses()
        self._addr_set_pages = self._get_addr_set_pages(addr_set)

    def find_invalid_accesses(self):
        """
        Search for referenced addresses outside of the currently
        defined memory space
        https://gist.github.com/starfleetcadet75/cdc512db77d7f1fb7ef4611c2eda69a5
        """
        listing = self.currentProgram.getListing()
        mem = self.dh.mem
        addr_set = AddressSet()
        for instr in listing.getInstructions(1):
            for ref in instr.getReferencesFrom():
                to_addr = ref.getToAddress()
                if not mem.contains(to_addr) and \
                   not to_addr.isStackAddress() and \
                   not to_addr.isRegisterAddress():
                    addr_set.add(to_addr)

        return addr_set

    def _get_addr_set_pages(self, addr_set):
        """
        Consolidate the addresses in an addr set
        and return an address set that specifies pages instead
        of individual addresses
        Note: only uses minAddress, not maxAddress
        """
        page_addrs = [i.minAddress.getOffset() & self._page_mask
                      for i in addr_set]
        page_addrs = list(set(page_addrs))
        page_addrs.sort()
        if len(page_addrs) == 0:
            return addr_set

        # #speedhack
        create_new_addr_func = self.dh.default_addr_space.getAddress
        new_addr_set = AddressSet()
        region = []
        last_addr = None
        for addr in page_addrs:
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

