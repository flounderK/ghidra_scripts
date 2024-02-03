# this is taken from one of the issues
# https://github.com/NationalSecurityAgency/ghidra/issues/3581

from __main__ import *

from ghidra.app.plugin.core.analysis import ConstantPropagationContextEvaluator
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSpace
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import Program
from ghidra.program.model.listing import ProgramContext
from ghidra.program.model.listing import Variable
from ghidra.program.model.pcode import Varnode
from ghidra.program.util import ContextEvaluator
from ghidra.program.util import SymbolicPropogator
from ghidra.program.util import VarnodeContext

from java_reflection_utils import get_accessible_java_field



class MemoryEnabledVarnodeContext(VarnodeContext):

    def __init__(self, program, programContext, spaceProgramContext):
        super(MemoryEnabledVarnodeContext, self).__init__(program, programContext,
                                                          spaceProgramContext)
        # accessing protected fields is a little bit painful
        memoryVals_field = get_accessible_java_field(VarnodeContext, "memoryVals")
        self.memoryVals = memoryVals_field.get(self)
        addrFactory_field = get_accessible_java_field(VarnodeContext, "addrFactory")
        self.addrFactory = addrFactory_field.get(self)

    def newGetMemoryValue(self, varnode):
        return self.getMemoryValue(varnode)


    def putMemoryValue(self, out, value):
        print("putMemoryValue called:")
        print("out: " + str(out) + " (" + str(out.getClass()) + ")")
        print("value: " + str(value) + " (" + str(value.getClass()) + ")")
        print("")
        super(MemoryEnabledVarnodeContext, self).putMemoryValue(out, value)

    def dumpMemory(self):
        for mem in self.memoryVals:
            for v in mem.keySet():
                print("# memory entry")
                print(str(v) + ": " + mem.get(v).toString())
                print("space id: " + str(v.getSpace()))
                print("offset: " + str(v.getOffset()))
                print("")

    def getAddressSpaceItself(self, name):
        return self.addrFactory.getAddressSpace(name)

class MemoryEnabledSymbolicPropogator(SymbolicPropogator):
    def __init__(self, program=None):
        if program is None:
            program = currentProgram
        super(MemoryEnabledSymbolicPropogator, self).__init__(program)
        program_context_field = get_accessible_java_field(SymbolicPropogator,
                                                          "programContext")
        program_context = program_context_field.get(self)
        space_context_field = get_accessible_java_field(SymbolicPropogator,
                                                        "spaceContext")
        space_context = space_context_field.get(self)
        new_context = MemoryEnabledVarnodeContext(program, program_context, space_context)
        context_field = get_accessible_java_field(SymbolicPropogator, "context")
        context_field.set(self, new_context)
        self.context = new_context
        context_field.get(self).setDebug(True)

    def getMemoryValue(self, toAddr, memory):
        return None

    def getContext(self):
        return self.context


func = currentProgram.getFunctionManager().getFunctionContaining(state.currentAddress)

if func is None:
    print("there is no current function!")
    raise Exception("")

start = func.getEntryPoint()

evl = ConstantPropagationContextEvaluator(monitor, True)
symEval = MemoryEnabledSymbolicPropogator(currentProgram)
symEval.flowConstants(start, func.getBody(), evl, True, monitor)

# // get the internal address space used by the propogator for ESP
espSpace = symEval.getContext().getAddressSpaceItself("RSP")
print("ESP address space: " + str(espSpace))

for v in func.getStackFrame().getLocals():
    print("local variable: " + v.toString())
    use = v.getFirstStorageVarnode()
    print("first use varnode: " + use.toString())
    # // create the varnode the internal propogator would have used for this local
    translatedOffset = use.getOffset() # + 0x100000000
    contextVarnode = Varnode(espSpace.getTruncatedAddress(translatedOffset, True), use.getSize())
    print("equivalent varnode: " + contextVarnode.toString())

    # // search for it!
    result = symEval.getContext().newGetMemoryValue(contextVarnode)
    if result is None:
        print("no symbolic entry found")
    else:
        print("found symbolic entry: " + result.toString())
    print("")
