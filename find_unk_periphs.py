from __main__ import *
from decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.symbol import FlowType, RefType
from ghidra.program.model.address import AddressSet
from collections import defaultdict
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


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
    def __init__(self, values=None, save_values=True, start=0, end=0, align_to=0x1000, pad_end_by=0):
        if values is None:
            values = []
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
    def __init__(self, group_incr=0x1000):
        self.group_incr = group_incr
        self.const_counts = defaultdict(lambda: 0)
        self.const_set = set()
        self.pmrs = []

    def find_code_accessed_consts(self):
        du = DecompUtils()

        # establish groups of constants
        for func in currentProgram.getFunctionManager().getFunctions(1):
            log.debug("looking at %s" % func.name)
            pcode_ops = du.get_pcode_for_function(func)
            if pcode_ops is None:
                continue
            vns = sum([list(i.inputs) for i in pcode_ops], [])
            for vn in vns:
                if vn.isConstant() or vn.isAddress():
                    # TODO: maybe fix this is it is negative
                    off = vn.getOffset()
                    self.const_counts[off] += 1
                    self.const_set.add(off)

    def find_defined_consts(self):
        listing = currentProgram.getListing()
        for dat in listing.getDefinedData(1):
            if dat.valueClass is None:
                val = dat.value
                if val is None:
                    continue
                int_val = val.getUnsignedValue()
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
        pmrs = [PseudoMemoryRegion(g) for g in const_groups]
        ptr_size = currentProgram.getDefaultPointerSize()
        self.pmrs = []
        for i in pmrs:
            if i.length == 0:
                continue
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

    pf = PeriphFinder()
    valid_pmrs = pf.find_periphs()
    ptr_size = currentProgram.getDefaultPointerSize()
    hex_ptr_size = (ptr_size*2)+2
    print("start end length aligned length")
    fmt = "%%#0%dx-%%#0%dx %%#010x %%#010x" % (hex_ptr_size, hex_ptr_size)
    for pmr in valid_pmrs:
        print(fmt % (pmr.start, pmr.end, pmr.length, align_up(pmr.length, 0x1000)))


if __name__ == "__main__":
    print_possible_periph_regions()
