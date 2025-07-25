from __main__ import *
import re
import struct
from ghidra.program.model.address import AddressSet


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


def to_two_u16s(val):
    pack_end = ">" if currentProgram.getMemory().isBigEndian() else "<"
    return struct.unpack(pack_end + "HH", struct.pack(pack_end + "I", val))


def rexp_pat_u8(val):
    return "\\x%02x" % val


def rexp_pat_for_value(val, nbytes):
    pat_list = []
    curr = val
    count = 0
    while count < nbytes:
        u8_val = curr & 0xff
        pat_list.append(rexp_pat_u8(u8_val))
        curr = curr >> 8
        count += 1
    is_big_end = currentProgram.getMemory().isBigEndian()
    if is_big_end:
        pat_list = pat_list[::-1]
    return "".join(pat_list)


def create_full_mem_addr_set():
    existing_mem_addr_set = AddressSet()
    for m_block in getMemoryBlocks():
        existing_mem_addr_set.add(m_block.getAddressRange())
    return existing_mem_addr_set


def large_scalar_search(search_val, scalar_mask=0xffffffffffffffff, max_scalar_distance=20, align=2):
    """
    Search for scalar values embedded in instructions that are split across multiple different instructions
    to store values larger than the instruction set will allow to fit as a single instruction immediate.

    This is currently a naiive and brittle approach, but has the potential to be much better.
      - It has a potential for false positives
      - is very dependent on architecture, endinness, signedness, and instruction encoding
      - right now it only fully supports values that are 8-bit aligned and are unsigned
      - currently hard coded to search for u16 values
    """
    # build regular expressions from the search_val the execute them to find every potential match
    full_mem_addr_set = create_full_mem_addr_set()
    matches_by_subval = {}
    # TODO: this is currently locked to u16 values, but eventually that should change
    for subval in to_two_u16s(search_val):
        # TODO: This doesn't account for a few different ways to pack values,
        # TODO: like a packed signed value or a signed value not aligned to 15 or 14 bits
        rexp = rexp_pat_for_value(subval & scalar_mask, nbytes=2)
        # TODO: this can be optimized to only run a single regex, but at the cost of having
        # TODO: to extract each value and do a few lookups to sort correctly by subval. easy now,
        # TODO: but would be much more work with non-8-bit aligned values
        matches = [i for i in findBytes(full_mem_addr_set, rexp, 100000, align, True)]
        matches_by_subval[subval] = matches
    # merge all of the matches into a unified list for grouping
    joined_matches = sum(matches_by_subval.values(), [])
    grouped = group_by_increment(joined_matches, max_scalar_distance, lambda a: a.getOffsetAsBigInteger())
    potential_related_groups = [i for i in grouped if len(i) > 1]
    # go through and do a "soft" validation of each group to make sure that all
    # of the subvals were matched for each group. If they haven't, this can't be the scalar
    # we are looking for
    related_groups = []
    for pot_rel_group in potential_related_groups:
        # this is a table of the subvalues that have been matched against in the current group
        seen_group_matches_table = {k: False for k in matches_by_subval.keys()}
        for curr_match_addr in pot_rel_group:
            for subval, match_addrs in matches_by_subval.items():
                if curr_match_addr in match_addrs:
                    seen_group_matches_table[subval] = True
        if all([v for v in seen_group_matches_table.values()]):
            related_groups.append(pot_rel_group)
    return related_groups


