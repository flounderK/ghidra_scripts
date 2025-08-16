from __main__ import *
from ghidra.app.tablechooser import TableChooserDialog
from ghidra.app.tablechooser import TableChooserExecutor
from ghidra.app.tablechooser import AddressableRowObject
from ghidra.app.tablechooser import AbstractComparableColumnDisplay
from ghidra.program.model.address import Address


class QuickRow(AddressableRowObject):
    def __init__(self, address):
        self._address = address
        self.fields = {}
        super(QuickRow, self).__init__()
    def getAddress(self):
        return self._address
    @property
    def address(self):
        return self._address
    @staticmethod
    def create(address, **kwargs):
        row = QuickRow(address)
        for k, v in kwargs.items():
            row.fields[k] = v
        return row


def new_column(name):
    class ValColumn(AbstractComparableColumnDisplay):
        COLUMN_NAME = None
        def __init__(self):
            super(ValColumn, self).__init__()
        @staticmethod
        def getColumnValue(o):
            return o.fields.get(ValColumn.COLUMN_NAME)
        @staticmethod
        def getColumnName():
            return ValColumn.COLUMN_NAME
    ValColumn.COLUMN_NAME = name
    return ValColumn()


class TabEx(TableChooserExecutor):
    def __init__(self):
        super(TabEx, self).__init__()
    def execute(rowObj):
        pass
    def rowSelected(self, obj):
        if isinstance(obj, list) and len(obj) > 0:
            addr = obj[0]
            if isinstance(addr, Address):
                goto(addr)
    @staticmethod
    def getButtonName():
        return "apply"


executor = TabEx()
dialog = createTableChooserDialog("name", executor, True)
dialog.addCustomColumn(new_column("Value"))
dialog.addCustomColumn(new_column("Description"))
dialog.add(QuickRow.create(toAddr(1), Value=1, Description="blah"))
state.tool.showDialog(dialog)
