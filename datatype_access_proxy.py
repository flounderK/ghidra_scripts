from __main__ import *
import struct
from datatype_utils import applyDataTypeAtAddress


def gen_name_to_field_map(dt):
    fields = [dt.getComponent(i) for i in range(dt.getNumComponents())]
    field_map = {}
    for field in fields:
        if field.fieldName is None:
            continue
        field_map[field.fieldName] = field
    return field_map



class DataAccessProxy:
    SIZE_CODES = {
        1: "B",
        2: "H",
        4: "I",
        8: "Q"
    }
    def __init__(self, datadb):
        self.listing = currentProgram.getListing()
        self.datadb = datadb
        self.datatype = datadb.dataType
        self._end_code = ">" if datadb.isBigEndian() else "<"
        self.field_map = {}
        if hasattr(self.datatype, "getNumComponents"):
            self.field_map = gen_name_to_field_map(self.datatype)

    def access_field_by_name(self, name):
        """
        Access DataComponent by name
        """
        field = self.field_map[name]
        comp = self.datadb.getComponentAt(field.getOffset())
        return comp

    def access_name_value(self, name):
        comp = self.access_field_by_name(name)
        val = comp.value
        if comp.isPointer():
            cu = self.listing.getCodeUnitAt(val)
            val = DataAccessProxy(cu)
        return val

    def proxy_from_field_name(self, name):
        return DataAccessProxy(self.access_field_by_name(name))

    def full_access(self, name):
        comp_names = list(name.split("."))[::-1]
        curr = self
        while len(comp_names) > 1:
            curr_name = comp_names.pop()
            curr = curr.proxy_from_field_name(curr_name)

        curr_name = comp_names.pop()
        return curr.access_name_value(curr_name)

    def __repr__(self):
        return "DAP:%s@%s" % (str(self.datadb), self.datadb.address)

    def __getitem__(self, name):
        return self.full_access(name)

    @property
    def value(self):
        return self.datadb.value



listing = currentProgram.getListing()
st = currentProgram.getSymbolTable()
sym = [i for i in st.getAllSymbols(1) if i.name == 'containing_type_inst'][0]
dat = listing.getCodeUnitAt(sym.address)
dap = DataAccessProxy(dat)
