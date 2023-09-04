# Search the address space of the current program for a pointer
#@author Clifton Wolfe
#@category Utils

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript
from ghidra.program.model.symbol import SourceType
from pointer_utils import PointerUtils

from __main__ import *


ptr_util = PointerUtils()

addr = askAddress("Address to search for", "Enter address to search for")

match_addrs = ptr_util.search_for_pointer(addr)
for addr in match_addrs:
    print("%s" % addr)
