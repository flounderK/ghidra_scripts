from __main__ import *

program = currentProgram 
refman = program.getReferenceManager()
count_d = {func: refman.getReferenceCountTo(func.getEntryPoint()) for func in program.getFunctionManager().getFunctions(1)}

count_dl = list(count_d.items())
count_dl.sort(key=lambda a: a[1], reverse=True)

for func, refcount in count_dl:
    print("%s: %d" % (func, refcount))
