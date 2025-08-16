# analyze constants in the program to find "hot spots" where there are many references near one another
from __main__ import *
from decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.symbol import FlowType, RefType
from ghidra.program.model.address import AddressSet
from ghidra.program.database.code import InstructionDB
from ghidra.app.tablechooser import TableChooserDialog
from ghidra.app.tablechooser import TableChooserExecutor
from ghidra.app.tablechooser import AddressableRowObject
from ghidra.app.tablechooser import AbstractComparableColumnDisplay
from ghidra.program.model.address import Address
from collections import defaultdict
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


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


def group_by_increment(iterable, group_incr, field_access=None, do_sort=True):
    """
    Identify series of values that increment/decrement
    within a bounds @group_incr, grouping them into lists.
    The comparison to determine whether a value belongs in a group is
        if (prev_val + group_incr) <= curr_val:

    @iterable: iterable. This must be sorted for this function to work correctly.
    @group_incr: amount to be added to a value to determine
    @field_access: optional function to run on each element of the iterable to get
                   a value to be compared.
    """
    if field_access is None:
        field_access = lambda a: a
    if do_sort is True:
        iterable.sort()
    grouped = []
    current = [iterable[0]]
    for i in range(1, len(iterable)):
        curr_val = field_access(iterable[i])
        prev_val = field_access(current[-1])
        if (prev_val + group_incr) >= curr_val:
            current.append(iterable[i])
        else:
            grouped.append(current)
            current = [iterable[i]]
    if current:
        grouped.append(current)
    return grouped


def bnot(n, numbits=None):
    if numbits is None:
        numbits = currentProgram.getDefaultPointerSize()*8
    return (1 << numbits) -1 -n


def align(val, align_to, numbits=None):
    if numbits is None:
        numbits = currentProgram.getDefaultPointerSize()*8
    return val & bnot(align_to - 1, numbits)


def align_up(val, align_to, numbits=None):
    if numbits is None:
        numbits = currentProgram.getDefaultPointerSize()*8
    aligned = align(val, align_to, numbits)
    if aligned < val:
        aligned += align_to
    return aligned


class PseudoMemoryRegion:
    def __init__(self, values=None, ref_count=0, exec_count=0, save_values=True, start=0, end=0, align_to=0x1000, pad_end_by=0):
        if values is None:
            values = []
        self.ref_count = ref_count
        self.exec_count = exec_count
        # python 2 list copy
        values = [i for i in values]
        values.sort()
        self.start = start
        self.end = end
        if values:
            self.start = values[0]
            self.end = values[-1]
        aligned_start = align(self.start, align_to)
        # resolves a bug with constants larger than pointer size
        if aligned_start != 0:
            self.start = aligned_start
        if save_values:
            self.values = values
        else:
            self.values = []
        self.length = (self.end + pad_end_by) - self.start
    def __repr__(self):
        return "PseudoMemoryRegion(%#x-%#x, length=%#x)" % (self.start, self.end, self.length)


class PeriphFinder:
    def __init__(self, group_incr=0x1000, addr_ranges=None):
        self.group_incr = group_incr
        self.const_counts = defaultdict(lambda: 0)
        self.exec_const_counts = defaultdict(lambda: 0)
        self.const_set = set()
        self.pmrs = []
        if addr_ranges is None:
            self.addr_ranges = []
        else:
            self.addr_ranges = addr_ranges

    def get_selected_functions(self):
        """
        return a list of functions in self.addr_range or a list of all functions
        """
        if not self.addr_ranges:
            # do everything if no functions are selected
            return currentProgram.getFunctionManager().getFunctions(1)
        funcs = set()
        for addr_range in self.addr_ranges:
            for addr in addr_range:
                func = getFunctionContaining(addr)
                if func is None:
                    continue
                funcs.add(func)
        return list(funcs)

    def find_code_accessed_consts(self):
        """
        Find constants accessed by pcode ops
        """
        du = DecompUtils()
        call_ops = [PcodeOpAST.CALL, PcodeOpAST.CALLIND]

        # establish groups of constants
        for func in self.get_selected_functions():
            log.debug("looking at %s" % func.name)
            pcode_ops = du.get_pcode_for_function(func)
            if pcode_ops is None:
                continue
            for op in pcode_ops:
                # vns = sum([list(i.inputs) for i in pcode_ops], [])
                vns = op.inputs
                for i, vn in enumerate(vns):
                    if not vn.isConstant() and not vn.isAddress():
                        continue
                    # TODO: maybe fix this if offset is negative
                    off = vn.getOffset()
                    self.const_counts[off] += 1
                    self.const_set.add(off)
                    # record if the ref was a call
                    if op.opcode in call_ops and i == 0:
                        self.exec_const_counts[off] += 1

    def get_selected_data(self):
        """
        return a list of defined data accessed or contained in self.addr_range or a list of all defined data
        """
        if not self.addr_ranges:
            listing = currentProgram.getListing()
            return listing.getDefinedData(1)
        funcs = self.get_selected_functions()
        return self.get_defined_data_for_funcs(funcs)

    def get_defined_data_for_funcs(self, funcs):
        """
        resolve data stored in literal pools
        """
        def_data = []
        listing = currentProgram.getListing()
        refman = currentProgram.getReferenceManager()
        for func in funcs:
            for addr_range in func.getBody():
                for addr in addr_range:
                    for ref in refman.getReferencesFrom(addr):
                        to_addr = ref.toAddress
                        dat = listing.getDefinedDataContaining(to_addr)
                        if dat is None:
                            continue
                        def_data.append(dat)
        return def_data

    def find_defined_consts(self):
        """
        Iterate through defined data and identify all consts
        """
        listing = currentProgram.getListing()
        for dat in self.get_selected_data():
            if dat.valueClass is None:
                val = dat.value
                if val is None:
                    if not dat.address:
                        continue
                    val = dat.address
                    int_val = val.getOffsetAsBigInteger()
                else:
                    if hasattr(val, "getUnsignedValue"):
                        int_val = val.getUnsignedValue()
                    elif hasattr(val, "getOffsetAsBigInteger"):
                        int_val = val.getOffsetAsBigInteger()
                # int_val = val.getUnsignedValue()
                self.const_set.add(int_val)
                self.const_counts[int_val] += 1
            if dat.isPointer():
                val = dat.value
                if val is None:
                    continue
                int_val = val.getOffsetAsBigInteger()
                self.const_set.add(int_val)
                self.const_counts[int_val] += 1
            # TODO: maybe handle structs, unions, and arrays

    def find_periphs(self):
        self.find_code_accessed_consts()
        self.find_defined_consts()
        sorted_consts = list(self.const_set)
        sorted_consts.sort()
        # group consts by how close they are to eachother
        const_groups = group_by_increment(sorted_consts, self.group_incr)
        pmrs = []
        for g in const_groups:
            ref_count = sum([self.const_counts.get(i, 0) for i in g])
            exec_count = sum([self.exec_const_counts.get(i, 0) for i in g])
            pmrs.append(PseudoMemoryRegion(g, ref_count=ref_count,
                                           exec_count=exec_count))
        ptr_size = currentProgram.getDefaultPointerSize()
        self.pmrs = []
        for i in pmrs:
            # cut because this removes valid regions with only a single access in them
            # if i.length == 0:
            #     continue
            if i.start < 0:
                continue
            if i.start.bit_length() > ptr_size*8:
                continue
            if i.end.bit_length() > ptr_size*8:
                continue
            self.pmrs.append(i)
        return self.pmrs


def print_possible_periph_regions():
    # get an address set for all current memory blocks
    existing_mem_addr_set = AddressSet()
    for m_block in getMemoryBlocks():
        # cut sections that are unused
        if not (m_block.isRead() or m_block.isWrite() or m_block.isExecute()):
            continue
        existing_mem_addr_set.add(m_block.getAddressRange())

    pf = PeriphFinder(addr_ranges=state.currentSelection)
    valid_pmrs = pf.find_periphs()
    ptr_size = currentProgram.getDefaultPointerSize()
    hex_ptr_size = (ptr_size*2)+2
    print("start end length aligned length refcount exec")
    fmt = "%%#0%dx - %%#0%dx %%#010x %%#010x refs=%%d exec=%%d" % (hex_ptr_size, hex_ptr_size)
    for pmr in valid_pmrs:
        print(fmt % (pmr.start, pmr.end, pmr.length, align_up(pmr.length, 0x1000), pmr.ref_count, pmr.exec_count))


def make_table_chooser_dialog():
    executor = TabEx()
    dialog = createTableChooserDialog("Choose Regions", executor, True)
    # dialog.addCustomColumn(new_column("address"))
    dialog.addCustomColumn(new_column("end"))
    dialog.addCustomColumn(new_column("length"))
    dialog.addCustomColumn(new_column("alignedLength"))
    dialog.addCustomColumn(new_column("refcount"))
    dialog.addCustomColumn(new_column("execRefcount"))

    pf = PeriphFinder(addr_ranges=state.currentSelection)
    valid_pmrs = pf.find_periphs()
    for pmr in valid_pmrs:
        kwargs = {
            "end": toAddr(pmr.end),
            "length": pmr.length,
            "alignedLength": align_up(pmr.length, 0x1000),
            "refcount": pmr.ref_count,
            "execRefcount": pmr.exec_count,
        }
        dialog.add(QuickRow.create(toAddr(pmr.start), **kwargs))
        # print("adding %s" % str(pmr))
    state.tool.showDialog(dialog)


if __name__ == "__main__":
    # print_possible_periph_regions()
    make_table_chooser_dialog()
