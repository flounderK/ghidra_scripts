from __main__ import *
from ghidra.program.model.address import AddressSet, AddressRangeImpl
from ghidra.program.model.symbol import RefType, SourceType
from collections import defaultdict
import re

func_to_regions = defaultdict(set)
regions_to_funcs = defaultdict(set)

mem_blocks = [m for m in getMemoryBlocks()]
refman = currentProgram.getReferenceManager()
for ref in refman.getReferenceIterator(toAddr(0)):
    if not ref.toAddress.isMemoryAddress():
        continue
    func = getFunctionContaining(ref.fromAddress)
    if func is None:
        continue
    for m_block in mem_blocks:
        if not m_block.addressRange.contains(ref.toAddress):
            continue
        func_to_regions[func].add(m_block.name)
        regions_to_funcs[m_block.name].add(func)

func_to_called_funcs = {k: k.getCalledFunctions(monitor) for k in func_to_regions.keys()}
leaf_funcs_to_regions = {k: v for k, v in func_to_regions.items() if len(func_to_called_funcs[k]) == 0}

# NOTE: making an assumption that these are the only regions that arent related to a periph
unrel_reg_set = set(["rom", "sram", ".text", ".data"])
periph_access_leaf_funcs = {k: v.difference(unrel_reg_set) for k, v in leaf_funcs_to_regions.items() if not unrel_reg_set.issuperset(v)}
for func, accessed_regions_set in periph_access_leaf_funcs.items():
    # ignore funcs that access more than one region
    if len(accessed_regions_set) > 1:
        continue
    region_name = list(accessed_regions_set)[0]
    region_name = re.sub("[?.:]", "_", region_name)
    if func.name.startswith("FUN_"):
        func.setName("interact_with_%s_%s" % (region_name, str(func.entryPoint)), SourceType.USER_DEFINED)
        continue
    if func.name.lower().find(region_name.lower()) == -1:
        func.setName("%s_interact_with_%s" % (func.name, region_name), SourceType.USER_DEFINED)
        continue
