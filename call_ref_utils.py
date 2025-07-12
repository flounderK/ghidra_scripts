
from __main__ import *

from collections import defaultdict
from ghidra.program.model.symbol import FlowType, RefType, SourceType, MemReferenceImpl
import re


def get_calling_addresses_to_address(address, program=None):
    """
    get the addresses that call @address
    """
    if program is None:
        program = currentProgram
    refman = program.getReferenceManager()
    calling_addrs = list()
    references = refman.getReferencesTo(address)
    for ref in references:
        ref_type = ref.getReferenceType()
        if ref_type.isCall() is False:
            continue
        calling_addrs.append(ref.fromAddress)
    return calling_addrs


def get_called_addresses_from_address(address, program=None):
    """
    get the addresses that call @address
    """
    if program is None:
        program = currentProgram
    refman = program.getReferenceManager()
    called_addrs = list()
    references = refman.getReferencesFrom(address)
    for ref in references:
        ref_type = ref.getReferenceType()
        if ref_type.isCall() is False:
            continue
        called_addrs.append(ref.toAddress)
    return called_addrs


def get_callsites_for_func_by_name(func_name, program=None):
    """
    Return a dictionary of {Function: [call address, ..]}
    of functions that call @func_name
    """
    if program is None:
        program = currentProgram

    # get all functions (including thunks) with the same name
    funcs = [i for i in program.getFunctionManager().getFunctions(1) \
             if i.name == func_name]

    callsites = defaultdict(list)
    for func in funcs:
        entry = func.getEntryPoint()
        calling_addresses = get_calling_addresses_to_address(entry, program)
        for calling_addr in calling_addresses:
            calling_func = getFunctionContaining(calling_addr)
            # ignore thunks, they should already be in the list
            # so they will be processed
            if calling_func.name == func_name:
                continue
            callsites[calling_func].append(calling_addr)
    return dict(callsites)


def function_calls_self(func, program=None):
    """
    Check if a function calls itself
    """
    if program is None:
        program = currentProgram
    entry = func.getEntryPoint()
    calling_addrs = get_calling_addresses_to_address(entry, program)
    return any([func.body.contains(a) for a in calling_addrs])


def get_all_functions_leading_to(func, program=None):
    """
    Get a list of all functions that could call into @func and
    any functions that call those functions, etc.
    """
    if program is None:
        program = currentProgram

    if func is None:
        return set()

    to_visit = set([func])
    visited = set()
    while to_visit:
        curr_func = to_visit.pop()
        entry = curr_func.getEntryPoint()
        calling_addrs = get_calling_addresses_to_address(entry, program)
        for calling_addr in calling_addrs:
            calling_func = getFunctionContaining(calling_addr)
            if calling_func in visited:
                continue
            if calling_func in to_visit:
                continue
            if calling_func == curr_func:
                continue
            to_visit.add(calling_func)
        visited.add(curr_func)

    func_calls_self = function_calls_self(func, program)
    # check if func calls itself to determine if it needs to be removed
    if func_calls_self is False:
        visited.remove(func)
    return visited


def get_all_functions_called_from(func, program=None):
    """
    Get a list of all functions called by @func and
    any functions that are called by those functions, etc.
    """
    if program is None:
        program = currentProgram

    if func is None:
        return set()

    to_visit = set([func])
    visited = set()
    while to_visit:
        curr_func = to_visit.pop()
        called_addrs = []
        for rang in curr_func.getBody():
            for addr in rang:
                called_addrs += list(get_called_addresses_from_address(addr, program=program))
        # called_addrs = curr_func.getCalledFunctions(monitor_inst)
        for called_addr in called_addrs:
            called_func = getFunctionContaining(called_addr)
            if called_func is None:
                continue
            if called_func in visited:
                continue
            if called_func in to_visit:
                continue
            if called_func == curr_func:
                continue
            to_visit.add(called_func)
        visited.add(curr_func)

    func_calls_self = function_calls_self(func, program)
    # check if func calls itself to determine if it needs to be removed
    if func_calls_self is False:
        visited.remove(func)
    return visited


def  add_unconditional_call_ref(call_addr, call_to_addr, primary=False):
    listing = currentProgram.getListing()
    COMMENT_PRE = 1
    call_to_addr_repr = ""
    func = getFunctionContaining(call_to_addr)
    if func is not None:
        call_to_addr_repr = func.name
    else:
        call_to_addr_repr = str(call_to_addr)
    comment_str = "indirect call to %s @ %s here" % (call_to_addr_repr, call_addr)
    existing_comment_str = listing.getComment(COMMENT_PRE, call_addr)
    rexp = re.compile("indirect call to .+ @ %s here" % call_addr)
    if existing_comment_str is not None and re.search(rexp, existing_comment_str) is None:
        comment_str = existing_comment_str +  "\n" + comment_str
    listing.setComment(call_addr, COMMENT_PRE, comment_str)
    ref_impl = MemReferenceImpl(call_addr, call_to_addr, RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0, primary)
    refman = currentProgram.getReferenceManager()
    refman.addReference(ref_impl)

