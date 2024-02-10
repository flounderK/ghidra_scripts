#!/usr/bin/env python3
import ghidra

from ghidra.program.model.symbol import FlowType, RefType
from ghidra.program.model.address import AddressSet

from __main__ import *
from collections import defaultdict
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)


def offset_list_from_address_list(addr_list):
    """
    Get a list of difference from each address in a list
    to the next entry in the list
    """
    # sorted_addr_list = sorted(addr_list)
    offset_list = []
    for ind in range(1, len(addr_list)):
        prev = addr_list[ind-1]
        curr = addr_list[ind]
        diff = curr.subtract(prev)
        offset_list.append(int(diff))
    return offset_list


addr_set = AddressSet()
for m_block in getMemoryBlocks():
    if not (m_block.isRead() or m_block.isWrite() or m_block.isExecute()):
        continue
    addr_set.add(m_block.getAddressRange())


refman = currentProgram.getReferenceManager()
current_image_base = currentProgram.getImageBase()
ref_iter = refman.getReferenceIterator(current_image_base)

to_external = []
computed_call_refs = []
computed_jump_refs = []
conditional_jump_refs = []
external_data_refs = []
for ref in ref_iter:
    to_addr = ref.toAddress
    # ignore all references to locations that fit within the
    # currently established address space
    if addr_set.contains(to_addr):
        continue
    # stack references are just references to an address space that
    # will exist at runtime, ignore
    if ref.isStackReference():
        continue
    to_external.append(ref)
    # a computed ref is expected to utilize an absolute address
    if ref.referenceType.isComputed():
        if ref.referenceType.isCall():
            # calls to function pointers
            computed_call_refs.append(ref)
        elif ref.referenceType.isJump():
            # likely trampolines or switch-case statements
            if ref.referenceType.isConditional():
                # expected to be switch statement
                conditional_jump_refs.append(ref)
            else:
                computed_jump_refs.append(ref)
    if ref.referenceType.isData():
        external_data_refs.append(ref)


computed_call_to_addrs = list(set([i.toAddress for i in computed_call_refs]))
computed_call_to_addrs.sort()
listing = currentProgram.getListing()

established_function_entrypoints = [i.getEntryPoint() for i in currentProgram.getFunctionManager().getFunctions(1)]
established_function_entrypoints.sort()


established_func_offsets = offset_list_from_address_list(established_function_entrypoints)

computed_addr_offsets = offset_list_from_address_list(computed_call_to_addrs)

computed_addr_range = sum(computed_addr_offsets)


conditional_jump_refs_by_func = defaultdict(list)
for ref in conditional_jump_refs:
    referring_func = getFunctionContaining(ref.fromAddress)
    if referring_func is None:
        log.warning("No function for %s" % str(ref))
        continue
    conditional_jump_refs_by_func[referring_func].append(ref)

conditional_jump_refs_by_func = dict(conditional_jump_refs_by_func)
conditional_jump_ref_offsets_by_func = {}
for k, refs in conditional_jump_refs_by_func.items():
    to_addrs = sorted([i.toAddress for i in refs])
    conditional_jump_ref_offsets_by_func[k] = offset_list_from_address_list(to_addrs)
# for func_addr in established_function_entrypoints:
#     curr_base = func_addr
#     for offset in computed_addr_offsets:




