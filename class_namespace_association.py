# Namespace Association and class analysis to improve C++ analysis from
# RecoverClassesFromRTTIScript.java and astrelsky/Ghidra-Cpp-Class-Analyzer.
# The script currently requires one of those to have already been performed,
# or for vtables to have either 'vtable' or 'vftable' in their label.
#
# The script is also a work in progress, so there will likely be improvements
# made, especially when it comes to inheritance structures, call graph
# analysis, and association of functions with a given class namespace.
#@author Clifton Wolfe
#@category C++

from collections import defaultdict
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.python import PythonScript

# TODO: Try to autofill class structrues based on thisptr


class ClassNamespaceAssociator:
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

        self._null = self.addr_space.getAddress(0)
        self._global_ns = currentProgram.getGlobalNamespace()

        self._thiscall_str = u'__thiscall'
        self._vftable_str = u'vftable'
        self._vtable_str = u'vtable'
        self._pure_virtual_str = u'pure_virtual'

        self._decomp_options = DecompileOptions()
        self._monitor = ConsoleTaskMonitor()
        self._ifc = DecompInterface()
        self._ifc.setOptions(self._decomp_options)

        # lsm = high_func.getLocalSymbolMap()
        # symbols = lsm.getSymbols()
        self.func_associations = defaultdict(set)
        self.multiple_inheritance_functions = defaultdict(set)
        # store all found vtables/vftables, regardless of duplicates
        self.vftable_entries = {}
        # store all functions associated with each namespace,
        # removing duplicates
        self.namespace_functions = defaultdict(set)

        self.class_syms = defaultdict(list)
        self._populate_namespace_associated_symbols()
        self.analyze_function_associations()

    def get_high_function(self, func, timeout=60):
        """
        Get a HighFunction for a given function
        """
        self._ifc.openProgram(func.getProgram())
        res = self._ifc.decompileFunction(func, timeout, self._monitor)
        high_func = res.getHighFunction()
        return high_func

    def _populate_namespace_associated_symbols(self):
        """
        Populate a defaultdict(list) with symbols associated
        with each Class namespace that is currently accessible
        """
        for namespace in self.sym_tab.getClassNamespaces():
            for s in self.sym_tab.getChildren(namespace.getSymbol()):
                self.class_syms[s.getParentSymbol().getName()].append(s)

    def analyze_function_associations(self):
        """
        Iterate each available class namespace to find labels/symbols
        called vtable/vftable,  and collect data on which
        class namespace each function can be associated with.
        """
        # clean up collected vftable entries to remove duplicates
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
                parent_namespace = s.getParentNamespace()
                self.vftable_entries[s] = vftable_entries
                # if multiple vtable/vftable symbols are found for the
                # same namespace, the association should still be made
                # in the odd occurrance that there are multiple separate
                # vftables for the same class
                for e in vftable_entries:
                    self.namespace_functions[parent_namespace].add(e)

                for func in vftable_entries:
                    if func == self._null:
                        continue

                    self.func_associations[func].add(namespace)

        # Find vtable functions that could fit into multiple namespaces
        # (this likely means they are inherited)
        for func, namespaces in self.func_associations.items():
            if len(namespaces) == 1:
                continue
            for n in namespaces:
                self.multiple_inheritance_functions[func].add(n)

    def set_function_associations(self, skip_thiscall_association=False):
        """
        Associate functions that are only ever in a single
        class namespace with that namespace, as non-virtual functions.

        The calling convention for functions is also set to `__thiscall`
        unless disabled.
        """
        # do the namespace association with each func
        for func, namespaces in self.func_associations.items():
            if len(namespaces) == 1:
                if not self.is_external(func):
                    self.set_parent_namespace_maybe_thunk(func, list(namespaces)[0])
            else:
                # TODO: try to identify longer inheritance
                # structures to pick the
                # base class to associate the function with
                virtual_namespaces = [n for n in namespaces if self._is_class_namespace_virtual(n)]
                # pick off easier associations that are only inherited by
                # non-virtual classes
                if len(virtual_namespaces) == 1:
                    if not self.is_external(func):
                        self.set_parent_namespace_maybe_thunk(func, list(virtual_namespaces)[0])

            if not skip_thiscall_association:
                self.set_calling_convention_maybe_thunk(func, self._thiscall_str)

        # search for and associate private functions with each class namespace
        for namespace in self.namespace_functions.keys():
            priv_funcs = self._find_private_function_of_class_namespace(namespace)
            for func in priv_funcs:
                if not self.is_external(func):
                    self.set_parent_namespace_maybe_thunk(func, namespace)

                if not skip_thiscall_association:
                    self.set_calling_convention_maybe_thunk(func, self._thiscall_str)

    def is_external(self, func):
        if func == self._null:
            return False
        dethunked = func
        if func.thunk:
            dethunked = func.getThunkedFunction(True)

        return dethunked.external

    def set_calling_convention_maybe_thunk(self, func, calling_convention):
        while func.thunk:
            func.setCallingConvention(calling_convention)
            func = func.getThunkedFunction(False)
        func.setCallingConvention(calling_convention)

    def set_parent_namespace_maybe_thunk(self, func, namespace):
        while func.thunk:
            func.setParentNamespace(namespace)
            func = func.getThunkedFunction(False)

        if not func.external:  # cant reparent external function
            func.setParentNamespace(namespace)

    def get_vftable_entries(self, vftable):
        """
        Get a list of function pointer entries for a given vftable/vtable.
        The returned list may also include Address(0) (NULL) entries,
        as the vtable likely includes an uninitialized function poiner.
        """
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

    def get_datatype_of_thisptr(self, func):
        """
        Get the datatype of a Function's `this` pointer.
        """
        if func.getCallingConvention().name != self._thiscall_str:
            return None
        high_func = self.get_high_function(func)
        prot = high_func.getFunctionPrototype()
        num_params = prot.getNumParams()
        if num_params == 0:
            return None
        maybe_this = prot.getParam(0)
        return maybe_this.getDataType()

    def _is_class_namespace_virtual(self, namespace):
        """
        Try to guess if a class namespace is virtual by looking for
        'pure_virtual' in the function names associated with its vtable
        """
        funcs = self.namespace_functions.get(namespace, [])
        for func in funcs:
            if func == self._null:
                continue

            if func.name.find(self._pure_virtual_str) != -1:
                return True

        return False

    def _find_private_function_of_class_namespace(self, namespace):
        """
        Check each function that is called by the vtable functions of
        the given namespace to see if it is only called by functions
        in that vtable or their decendant functions.

        TODO: The graph traversal portion of this function is likely
        better implemented in java, so decendant call analysis is not
        implemented yet. Instead it is just a single call down for now.

        TODO: May need to check references to the called function as well

        TODO: handle thunks
        """
        namespace_functions = self.namespace_functions.get(namespace, set())
        found_private_functions = set()
        for func in namespace_functions:
            if func == self._null:
                continue
            called_functions = func.getCalledFunctions(self._monitor)
            for called_func in called_functions:
                calling_functions = set(called_func.getCallingFunctions(self._monitor))
                if calling_functions.issubset(namespace_functions):
                    found_private_functions.add(called_func)

        return found_private_functions


# from class_mapper import ClassNamespaceAssociator
# ca = ClassNamespaceAssociator(currentProgram)
# ca.set_function_associations()

if __name__ == '__main__':
    ca = ClassNamespaceAssociator(currentProgram)
    ca.set_function_associations()
    print("Done Running!")

# funcs = ca.get_vftable_entries(cm.class_syms[u'ActiveLoggerImpl'][2])
# func = funcs[0]
# datatype = ca.get_datatype_of_thisptr(func)
# base_datatype_name = datatype.displayName.replace(' *', '')
# [b] = [i for i in ca.dtm.getAllStructures() if i.getName() == base_datatype_name]
