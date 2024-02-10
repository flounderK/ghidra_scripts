# Print all of the locations in the binary where indexing can be detected
#

from __main__ import *
from decomp_utils import find_all_ptradds

funcs_with_ptradd = find_all_ptradds()

for func, ptradd_addrs in funcs_with_ptradd.items():
    print("%s" % func.name)
    for addr in ptradd_addrs:
        print("%s" % str(addr))
    print("")

