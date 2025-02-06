# Search the address space of the current program for a pointer
#@author Clifton Wolfe
#@keybinding ctrl 0
#@category Utils

from ghidra.program.model.symbol import SourceType
from pointer_utils import createPointerUtils
import logging

from __main__ import *

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


selection = state.currentSelection
if selection is None:
    log.debug("No selection detected, asking for address")
    addr = askAddress("Address to search for",
                      "Enter address to search for")
else:
    addr = selection.minAddress

log.info("[+] Searching for %s", addr)

ptr_util = createPointerUtils()

match_addrs = ptr_util.search_for_pointer(addr)
for addr in match_addrs:
    print("%s" % addr)
