from __main__ import *
import json
from collections import defaultdict
from ghidra.program.database.symbol import FunctionSymbol

st = currentProgram.getSymbolTable()
sym_serial = list()
for sym in st.getAllSymbols(1):
    addr = sym.getAddress()
    if addr.isExternalAddress():
        continue
    if not isinstance(sym, FunctionSymbol):
        continue
    dat = {}
    addr_int = int(sym.offsetAsBigInteger)
    if isinstance(sym, FunctionSymbol):
        func = getFunctionContaining(addr)
        if func.isThunk():
            continue
        dat['ranges'] = [[int(i.minAddress.offsetAsBigInteger),
                          int(i.maxAddress.offsetAsBigInteger)] for i in func.getBody()]
    dat["name"] = sym.name
    dat["addr"] = addr_int
    sym_serial.append(dat)

file_obj = askFile("out file", "select")
output_path = file_obj.toString()
with open(output_path, "w") as f:
    f.write(json.dumps(sym_serial, indent=2))
  
