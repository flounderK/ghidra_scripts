from __main__ import *
from decomp_utils import DecompUtils
import json
from collections import defaultdict
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import AddressSet
from ghidra.program.model.address import AddressRangeImpl
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.symbol import SymbolType
import os
import re


def get_function_call_graph_map():
    call_map = defaultdict(set)
    for func in currentProgram.getFunctionManager().getFunctions(1):
        func_key = func.getEntryPoint()
        for called_func in func.getCalledFunctions(monitor):
            called_key = called_func.getEntryPoint()
            call_map[func_key].add(called_key)

    call_map = dict(call_map)
    serializable_call_map = {k: list(v) for k, v in call_map.items()}
    return serializable_call_map


def get_code_block_sources(code_block):
    """
    block.SimpleSourceReferenceIterator is not iterable
    """
    sources = []
    source_iterator = code_block.getSources(monitor)
    while source_iterator.hasNext():
        sources.append(source_iterator.next())
    return sources


def get_code_block_dests(code_block):
    """
    block.SimpleSourceReferenceIterator is not iterable
    """
    dests = []
    dest_iterator = code_block.getDestinations(monitor)
    while dest_iterator.hasNext():
        dests.append(dest_iterator.next())
    return dests


def get_code_block_graph_map():
    block_map = defaultdict(set)




du = DecompUtils()
