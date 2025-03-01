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
        numbits = currentProgram.getDefaultPointerSize()
    return (1 << numbits) -1 -n


def align(val, align_to, numbits=None):
    if numbits is None:
        numbits = currentProgram.getDefaultPointerSize()
    return val & bnot(align_to - 1, numbits)



class PseudoMemoryRegion:
    def __init__(self, values=None, start=0, end=0, align_to=0x1000, pad_end_by=0):
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
        self.start = align(self.start, align_to)
        self.values = values
        self.length = (self.end + pad_end_by) - self.start
    def __repr__(self):
        return "PseudoMemoryRegion(%#x-%#x, length=%#x)" % (self.start, self.end, self.length)



du = DecompUtils()

const_counts = defaultdict(lambda: 0)
const_set = set()

GROUP_INCR = 0x1000-1

# establish groups of constants
for func in currentProgram.getFunctionManager().getFunctions(1):
    log.debug("looing at %s" % func.name)
    pcode_ops = du.get_pcode_for_function(func)
    if pcode_ops is None:
        continue
    vns = sum([list(i.inputs) for i in pcode_ops], [])
    for vn in vns:
        if vn.isConstant() or vn.isAddress():
            # TODO: maybe fix this is it is negative
            off = vn.getOffset()
            const_counts[off] += 1
            const_set.add(off)

sorted_consts = list(const_set)
sorted_consts.sort()

const_groups = group_by_increment(sorted_consts, GROUP_INCR)

pmrs = [PseudoMemoryRegion(g) for g in const_groups]
ptr_size = currentProgram.getDefaultPointerSize()
[i for i in pmrs if i.length > 0 and i.start >= 0 and i.start.bit_length() <= ptr_size]


# get an address set for all current memory blocks
existing_mem_addr_set = AddressSet()
for m_block in getMemoryBlocks():
    # cut sections that are unused
    if not (m_block.isRead() or m_block.isWrite() or m_block.isExecute()):
        continue
    existing_mem_addr_set.add(m_block.getAddressRange())


