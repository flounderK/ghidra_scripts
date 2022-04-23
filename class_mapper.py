"""
This script is meant to further the analysis of c++ classes
performed by
RecoverClassesFromRTTIScript.java and astrelsky/Ghidra-Cpp-Class-Analyzer.

"""

from collections import defaultdict
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI


class ClassMapper:
    def __init__(self, currentProgram):
        self.fm = currentProgram.getFunctionManager()
        self.dtm = currentProgram.getDataTypeManager()
        self.namespace_manager = currentProgram.getNamespaceManager()
        self.addr_fact = currentProgram.getAddressFactory()
        self.addr_space = self.addr_fact.getDefaultAddressSpace()
        self.mem = currentProgram.getMemory()
        self.sym_tab = currentProgram.getSymbolTable()

        self.ptr_size = self.addr_space.getPointerSize()
        if self.ptr_size == 4:
            self._get_ptr_size = self.mem.getInt
        elif self.ptr_size == 8:
            self._get_ptr_size = self.mem.getLong

        self._thiscall_str = u'__thiscall'
        self._vftable_str = u'vftable'
        self._vtable_str = u'vtable'

        self._decomp_options = DecompileOptions()
        self._monitor = ConsoleTaskMonitor()
        self._ifc = DecompInterface()
        self._ifc.setOptions(self._decomp_options)

        # lsm = high_func.getLocalSymbolMap()
        # symbols = lsm.getSymbols()
        self.func_associations = defaultdict(set)
        self.multiple_inheritance = defaultdict(set)
        self.vftable_entries = {}

        self.class_syms = defaultdict(list)
        self.get_associated_symbols()

    def get_high_function(self, func, timeout=60):
        self._ifc.openProgram(func.getProgram())
        res = self._ifc.decompileFunction(func, timeout, self._monitor)
        high_func = res.getHighFunction()
        return high_func

    def get_associated_symbols(self):
        for namespace in self.sym_tab.getClassNamespaces():
            for s in self.sym_tab.getChildren(namespace.getSymbol()):
                self.class_syms[s.getParentSymbol().getName()].append(s)

    def associate_vftable_functions_with_namespace(self):
        null_addr = self.addr_space.getAddress(0)
        for namespace in self.sym_tab.getClassNamespaces():
            for s in self.sym_tab.getChildren(namespace.getSymbol()):
                usable_vtable_symbol = False
                if s.name.find(self._vftable_str) != -1:
                    usable_vtable_symbol = True

                if s.name.find(self._vtable_str) != -1:
                    usable_vtable_symbol = True

                if not usable_vtable_symbol:
                    continue

                vftable_entries = self.get_vftable_entries(s)
                self.vftable_entries[s] = vftable_entries
                for func in vftable_entries:
                    if func == null_addr:
                        continue

                    self.func_associations[func].add(namespace)

        for func, namespaces in self.func_associations.items():
            if len(namespaces) == 1:
                func.setParentNamespace(list(namespaces)[0])
            else:
                for n in namespaces:
                    self.multiple_inheritance[func].add(n)

            func.setCallingConvention(self._thiscall_str)

    def get_vftable_entries(self, vftable):
        vftable_addr = vftable.getAddress()
        if vftable.name.find(self._vtable_str) != -1:
            vftable_addr = vftable_addr.add(self.ptr_size*2)
        addr = vftable_addr
        funcs = []
        while True:
            maybe_func_addr_val = self._get_ptr_size(addr)
            maybe_func_addr = self.addr_space.getAddress(maybe_func_addr_val)
            func = self.fm.getFunctionAt(maybe_func_addr)
            # if the ptr is a null ptr (uninitialized) or points
            # to a function, add it. Otherwise, assume the vtable is done
            if func is None:
                if maybe_func_addr_val == 0:
                    func = self.addr_space.getAddress(0)
                else:
                    break
            funcs.append(func)
            addr = addr.add(self.ptr_size)
        return funcs

    def get_datatype_of_thisptr(self, high_func):
        prot = high_func.getFunctionPrototype()
        num_params = prot.getNumParams()
        if num_params == 0:
            return None
        maybe_this = prot.getParam(0)
        return maybe_this.getDataType()

# import class_mapper
# cm = class_mapper.ClassMapper(currentProgram)
# cm.associate_vftable_functions_with_namespace()

# funcs = cm.get_vftable_entries(cm.class_syms[u'ActiveLoggerImpl'][2])
# func = funcs[0]
# high_func = cm.get_high_function(func)
# datatype = cm.get_datatype_of_thisptr(high_func)
# base_datatype_name = datatype.displayName.replace(' *', '')
# [b] = [i for i in cm.dtm.getAllStructures() if i.getName() == base_datatype_name]
