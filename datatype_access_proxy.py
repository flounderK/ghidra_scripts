from __main__ import *
from datatype_utils import applyDataTypeAtAddress


def gen_name_to_field_map(dt):
    if not hasattr(dt, "getNumComponents"):
        return {}
    fields = [dt.getComponent(i) for i in range(dt.getNumComponents())]
    field_map = {}
    for field in fields:
        if field.fieldName is None:
            continue
        field_map[field.fieldName] = field
    return field_map


class DataAccessProxy:
    def __init__(self, datadb):
        self.listing = currentProgram.getListing()
        self.datadb = datadb
        self.datatype = datadb.dataType
        self.field_map = {}
        if hasattr(self.datatype, "getNumComponents"):
            self.field_map = gen_name_to_field_map(self.datatype)

    def field(self, name):
        """
        Access DataComponent by name
        """
        field = self.field_map[name]
        comp = self.datadb.getComponentAt(field.getOffset())
        return comp

    def name_value(self, name):
        comp = self.field(name)
        val = comp.value
        if comp.isPointer() and val != toAddr(0):
            # TODO handle function pointers
            cu = self.listing.getCodeUnitAt(val)
            val = DataAccessProxy(cu)
        return val

    def proxy_field(self, name):
        dap = DataAccessProxy(self.field(name))
        if dap.isPointer():
            dap = self.name_value(name)
        return dap

    def full_proxy_access(self, name):
        comp_names = list(name.split("."))[::-1]
        curr = self
        while len(comp_names) > 1:
            curr_name = comp_names.pop()
            curr = curr.proxy_field(curr_name)

        curr_name = comp_names.pop()
        return curr.name_value(curr_name)

    def isPointer(self):
        if hasattr(self.datadb, "isPointer") and self.datadb.isPointer():
            return True
        return False

    def __repr__(self):
        return "DAP:%s@%s" % (str(self.datadb), self.datadb.address)

    def __getitem__(self, name):
        return self.full_proxy_access(name)

    @property
    def value(self):
        return self.datadb.value



listing = currentProgram.getListing()
st = currentProgram.getSymbolTable()
sym = [i for i in st.getAllSymbols(1) if i.name == 'containing_type_inst'][0]
dat = listing.getCodeUnitAt(sym.address)
dap = DataAccessProxy(dat)
