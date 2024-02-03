
from __main__ import *
from ghidra.program.model.block import BasicBlockModel, CodeBlockIterator
from ghidra.program.model.symbol import FlowType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor



def block_loops_to_self(block, monitor_inst=None):
    """
    Check if a block jumps back to it self
    """
    if monitor_inst is None:
        monitor_inst = monitor
    block_iter = block.getDestinations(monitor_inst)
    while block_iter.hasNext():
        if monitor_inst.isCancelled():
            break
        block_ref = block_iter.next()
        flow_type = block_ref.getFlowType()
        # TODO: indirection might be valid here, check
        if flow_type.isCall() is True or flow_type.isIndirect() is True:
            continue
        next_block = block_ref.getDestinationBlock()
        if next_block is None:
            continue
        if next_block == block:
            return True
    return False


def is_addr_in_loop(addr, program=None, monitor_inst=None):
    """
    Check if an address is in a basic loop within the current function.
    Untested
    """
    if program is None:
        program = currentProgram
    if monitor_inst is None:
        monitor_inst = monitor
    bbm = BasicBlockModel(program)
    start_blocks = list(bbm.getCodeBlocksContaining(addr, monitor_inst))
    # leave early if any of the first blocks just jump to themselves
    if any([block_loops_to_self(b) for b in start_blocks]) is True:
        return True

    # do a DFS to find all blocks that lead up to the starting blocks
    to_visit = set(start_blocks)
    visited = set()
    while to_visit:
        if monitor_inst.isCancelled():
            break
        block = to_visit.pop()
        block_iter = block.getSources(monitor_inst)
        while block_iter.hasNext():
            if monitor_inst.isCancelled():
                break
            block_ref = block_iter.next()
            flow_type = block_ref.getFlowType()
            # TODO: indirection might be valid here, check
            if flow_type.isCall() is True or flow_type.isIndirect() is True:
                continue
            next_block = block_ref.getSourceBlock()
            if next_block is None:
                continue
            if next_block in visited:
                continue
            if next_block in to_visit:
                continue
            if next_block == block:
                continue
            to_visit.add(next_block)
        visited.add(block)

    back_blocks = visited

    # do a second DFS to get all of the blocks forward from the starting
    # blocks. Exits early if a block that leads to the start blocks is reached
    to_visit = set(start_blocks)
    visited = set()
    while to_visit:
        if monitor_inst.isCancelled():
            break
        block = to_visit.pop()
        block_iter = block.getDestinations(monitor_inst)
        while block_iter.hasNext():
            if monitor_inst.isCancelled():
                break
            block_ref = block_iter.next()
            flow_type = block_ref.getFlowType()
            if flow_type.isCall() is True or flow_type.isIndirect() is True:
                continue
            next_block = block_ref.getDestinationBlock()
            if next_block is None:
                continue
            # extra check to exit early for found loops to reduce total
            # iterations
            if next_block in back_blocks:
                return True
            if next_block in visited:
                continue
            if next_block in to_visit:
                continue
            if next_block == block:
                continue
            to_visit.add(next_block)
        visited.add(block)
    #fwd_blocks = visited
    return False


