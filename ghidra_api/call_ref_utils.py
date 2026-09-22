from ._compat import CAUGHT_ERRORS, get_function_containing, resolve_program

from collections import defaultdict
from ghidra.program.model.symbol import RefType, SourceType, MemReferenceImpl
import re


def get_calling_addresses_to_address(address, program=None):
    """
    get the addresses that call @address
    """
    program = resolve_program(program)
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
    program = resolve_program(program)
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
    program = resolve_program(program)

    # get all functions (including thunks) with the same name
    funcs = [i for i in program.getFunctionManager().getFunctions(1) \
             if i.name == func_name]

    callsites = defaultdict(list)
    for func in funcs:
        entry = func.getEntryPoint()
        calling_addresses = get_calling_addresses_to_address(entry, program)
        for calling_addr in calling_addresses:
            calling_func = get_function_containing(program, calling_addr)
            # a call reference can originate outside any defined function
            # (e.g. a PLT stub or a region that was never turned into a
            # function), in which case there is no caller to attribute it to
            if calling_func is None:
                continue
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
    program = resolve_program(program)
    entry = func.getEntryPoint()
    calling_addrs = get_calling_addresses_to_address(entry, program)
    return any([func.body.contains(a) for a in calling_addrs])


def get_all_functions_leading_to(func, program=None):
    """
    Get a list of all functions that could call into @func and
    any functions that call those functions, etc.
    """
    program = resolve_program(program)

    if func is None:
        return set()

    to_visit = set([func])
    visited = set()
    while to_visit:
        curr_func = to_visit.pop()
        entry = curr_func.getEntryPoint()
        calling_addrs = get_calling_addresses_to_address(entry, program)
        for calling_addr in calling_addrs:
            calling_func = get_function_containing(program, calling_addr)
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
    program = resolve_program(program)

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
            called_func = get_function_containing(program, called_addr)
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


def resolve_thunk(func):
    """The function a thunk ultimately forwards to, or @func itself.

    A PLT stub or a jump-only wrapper shows up as its own Function in Ghidra,
    so a naive call graph has every import behind a one-vertex detour. The
    thunk chain is followed to its end; a thunk whose target is unknown is
    returned as-is.
    """
    if func is None or not func.isThunk():
        return func
    target = func.getThunkedFunction(True)
    return target if target is not None else func


# How far past a referenced address to look for function pointers when no
# data unit or symbol says where the table ends. Busybox's applet table is
# about 3KB; interrupt vector tables are under 1KB.
TABLE_SCAN_LIMIT = 8192


def _is_arm(program):
    """Whether pointers may carry a Thumb bit. Only on ARM does an odd
    pointer mean "the even address, in Thumb mode"; an x86 function can sit
    at an odd address in its own right."""
    return "ARM" in str(program.getLanguage().getProcessor()).upper()


def _code_address_candidates(program, value):
    """The addresses a stored code pointer may mean: the value itself, and
    on ARM the value with its Thumb bit cleared."""
    if value & 1 and _is_arm(program):
        return (value, value & ~1)
    return (value,)


def _function_at_pointer(program, value):
    """The function a pointer-sized word points at, or None.

    Tries the value as-is and, on ARM, with the low bit cleared, since a
    Thumb function's address is stored with bit 0 set.
    """
    funcman = program.getFunctionManager()
    space = program.getAddressFactory().getDefaultAddressSpace()
    for candidate in _code_address_candidates(program, value):
        try:
            addr = space.getAddress(candidate)
        except CAUGHT_ERRORS:
            return None
        func = funcman.getFunctionAt(addr)
        if func is not None:
            return func
    return None


def _is_table_boundary_symbol(symbol):
    """Whether a symbol marks where one table ends and something else
    begins. Ghidra's own ``PTR_``/``DAT_`` labels on the entries of a table
    it has already discovered do not; a user's or the loader's symbols do."""
    source = symbol.getSource()
    return source == SourceType.USER_DEFINED or source == SourceType.IMPORTED


def _table_range(program, addr):
    """The address range a pointer table at @addr plausibly spans.

    Returns None for something that cannot be a table: a string, or an
    address outside memory. A composite or array data unit (a struct, a
    typed pointer array, a sized ``undefined1[N]`` from an ELF symbol) is
    its own extent. Otherwise the
    table is a run of adjacent pointer-sized slots -- undefined bytes that
    hold zero or an address in memory, or the individual pointers Ghidra's
    address-table analyzer already carved out -- that ends at the first slot
    holding some other kind of data or value, carrying a user or imported
    symbol, at the block's end, or at TABLE_SCAN_LIMIT. Stopping at the
    first non-address word is what keeps a walk that starts in one table
    from running on into the next one.
    """
    listing = program.getListing()
    symbols = program.getSymbolTable()
    memory = program.getMemory()
    pointer_size = program.getDefaultPointerSize()
    data = listing.getDataContaining(addr)
    if data is not None and data.hasStringValue():
        return None
    if data is not None and data.getLength() > pointer_size:
        return data.getMinAddress(), data.getMaxAddress()

    def holds_address(slot_addr):
        value = _read_pointer(memory, slot_addr, pointer_size)
        if value is None:
            return False
        if value == 0:
            return True
        space = program.getAddressFactory().getDefaultAddressSpace()
        for candidate in _code_address_candidates(program, value):
            try:
                if memory.contains(space.getAddress(candidate)):
                    return True
            except CAUGHT_ERRORS:
                pass
        return False

    start = addr
    if start.getOffset() % pointer_size:
        start = start.add(pointer_size - start.getOffset() % pointer_size)
    block = memory.getBlock(start)
    if block is None:
        return None
    limit = start.add(TABLE_SCAN_LIMIT - 1)
    if limit.compareTo(block.getEnd()) > 0:
        limit = block.getEnd()
    end = start.add(pointer_size - 1)
    cursor = start
    while True:
        next_slot = cursor.add(pointer_size)
        if next_slot.add(pointer_size - 1).compareTo(limit) > 0:
            break
        slot = listing.getDataContaining(next_slot)
        if slot is not None:
            if slot.getLength() > pointer_size:
                break  # a string, struct or array: not part of this table
            if slot.getMinAddress().compareTo(next_slot) != 0:
                break  # mid-element: the slots have gone out of step
            if slot.isDefined() and not slot.isPointer() \
                    and slot.getLength() != pointer_size:
                break
            if not slot.isDefined() and not holds_address(next_slot):
                break
        elif listing.getInstructionContaining(next_slot) is not None:
            break
        elif not holds_address(next_slot):
            break
        boundary = False
        for symbol in symbols.getSymbols(next_slot):
            if _is_table_boundary_symbol(symbol):
                boundary = True
                break
        if boundary:
            break
        cursor = next_slot
        end = cursor.add(pointer_size - 1)
    return start, end


def _read_pointer(memory, addr, pointer_size):
    """The unsigned pointer-sized word at @addr, or None if unreadable."""
    try:
        if pointer_size == 8:
            return memory.getLong(addr) & 0xffffffffffffffff
        if pointer_size == 4:
            return memory.getInt(addr) & 0xffffffff
        return memory.getShort(addr) & 0xffff
    except CAUGHT_ERRORS:
        return None


def _create_function_at(program, addr):
    """Make a function at @addr, which must be code outside every existing
    function and not defined data (an ARM literal pool sits in an executable
    block too), and return it. The caller owns the transaction."""
    from ghidra.app.cmd.function import CreateFunctionCmd
    funcman = program.getFunctionManager()
    if funcman.getFunctionContaining(addr) is not None:
        return None
    if program.getListing().getDefinedDataContaining(addr) is not None:
        return None
    if CreateFunctionCmd(addr).applyTo(program):
        return funcman.getFunctionAt(addr)
    return None


def get_function_pointers_in_data(addr, program=None, depth=1, create=False,
                                  _cache=None):
    """Functions whose entry points are stored in the data at @addr.

    Reads every aligned pointer-sized word in the table that @addr belongs
    to (see :func:`_table_range`) and keeps the ones that are function entry
    points. With @depth greater than one, a word pointing at other data is
    followed and that data scanned too, which is how a driver's ``ops``
    struct is reached through the device struct that points at it.

    With @create, a word pointing at code that lies outside every existing
    function gets a function created there and counted. Busybox's applet
    table names 263 entry points of which Ghidra had made functions for 86;
    the rest were never referenced by anything but the table. The caller
    owns the transaction. A word pointing into an existing function (a
    switch's jump table) is never touched.

    Nothing here needs the table to be typed: ``configuration_table`` in a
    static zlib is an ``undefined1[160]`` with no references out of it, and
    the pointers inside are still found.
    """
    program = resolve_program(program)
    if depth <= 0:
        return []
    if _cache is None:
        _cache = {}
    memory = program.getMemory()
    if not memory.contains(addr):
        return []
    table = _table_range(program, addr)
    if table is None:
        return []
    start, end = table
    key = (str(start), depth)
    if key in _cache:
        return _cache[key]
    _cache[key] = []  # guards against cycles while this table is scanned
    space = program.getAddressFactory().getDefaultAddressSpace()

    pointer_size = program.getDefaultPointerSize()
    found = {}
    nested = []
    cursor = start
    if start.getOffset() % pointer_size:
        cursor = start.add(pointer_size - start.getOffset() % pointer_size)
    while cursor.compareTo(end) <= 0 and end.subtract(cursor) + 1 >= pointer_size:
        value = _read_pointer(memory, cursor, pointer_size)
        if value is None:
            break
        func = _function_at_pointer(program, value)
        if func is None and create and value:
            for candidate in _code_address_candidates(program, value):
                try:
                    target = space.getAddress(candidate)
                except CAUGHT_ERRORS:
                    continue
                block = memory.getBlock(target)
                if block is not None and block.isExecute():
                    func = _create_function_at(program, target)
                    if func is not None:
                        break
        if func is not None:
            found.setdefault(str(func.getEntryPoint()), func)
        elif depth > 1 and value:
            nested.append(value)
        cursor = cursor.add(pointer_size)

    if depth > 1:
        for value in nested:
            try:
                target = space.getAddress(value)
            except CAUGHT_ERRORS:
                continue
            if not memory.contains(target):
                continue
            block = memory.getBlock(target)
            if block is not None and block.isExecute():
                continue  # a pointer into code that is not an entry point
            for func in get_function_pointers_in_data(target, program, depth - 1,
                                                      create, _cache):
                found.setdefault(str(func.getEntryPoint()), func)

    result = list(found.values())
    _cache[key] = result
    return result


def get_called_functions(func, program=None, include_data_refs=False,
                         resolve_thunks=True, table_depth=0,
                         create_table_functions=False, _table_cache=None):
    """The functions @func calls, as a list with no duplicates.

    Walks only the addresses in the body that have references out of them
    (``getReferenceSourceIterator``) rather than every address, which is what
    makes it usable across a whole program. A call to a thunk is reported as
    the thunked function unless @resolve_thunks is False.

    With @include_data_refs, a pointer reference from the body to a function
    entry point counts as well: taking the address of a callback is the only
    link the reference manager has to it, and for callback-driven firmware
    that link is usually the one that matters.

    With @table_depth of one or more, a reference from the body to data is
    followed into that data and any function pointers stored there count as
    calls (see :func:`get_function_pointers_in_data`); two follows a pointer
    in that data one hop further. This is what attaches a dispatch table's
    targets to the function that indexes the table.
    @create_table_functions additionally makes functions of table entries
    -- and, with @include_data_refs, of directly taken code pointers -- that
    point at code outside every function (the caller owns the transaction).
    @_table_cache lets a caller building a whole graph share the table scans
    across functions.
    """
    program = resolve_program(program)
    refman = program.getReferenceManager()
    funcman = program.getFunctionManager()
    memory = program.getMemory()
    callees = {}
    if table_depth and _table_cache is None:
        _table_cache = {}

    def add(callee):
        if resolve_thunks:
            callee = resolve_thunk(callee)
        key = str(callee.getEntryPoint())
        if key not in callees:
            callees[key] = callee

    addresses = refman.getReferenceSourceIterator(func.getBody(), True)
    while addresses.hasNext():
        from_addr = addresses.next()
        for ref in refman.getReferencesFrom(from_addr):
            ref_type = ref.getReferenceType()
            to_addr = ref.getToAddress()
            if ref_type.isCall():
                callee = funcman.getFunctionAt(to_addr)
                if callee is not None:
                    add(callee)
                continue
            if not ref_type.isData():
                continue
            callee = funcman.getFunctionAt(to_addr)
            if callee is None and include_data_refs and create_table_functions \
                    and memory.contains(to_addr):
                # a pointer to code nothing else refers to: busybox's main,
                # handed to __libc_start_main and never called directly
                block = memory.getBlock(to_addr)
                if block is not None and block.isExecute():
                    callee = _create_function_at(program, to_addr)
            if callee is not None:
                if include_data_refs:
                    add(callee)
                continue
            if table_depth and memory.contains(to_addr):
                block = memory.getBlock(to_addr)
                if block is not None and block.isExecute():
                    continue
                for pointed in get_function_pointers_in_data(
                        to_addr, program, table_depth, create_table_functions,
                        _table_cache):
                    add(pointed)
    return list(callees.values())


def add_unconditional_call_ref(call_addr, call_to_addr, primary=False,
                               program=None):
    program = resolve_program(program)
    listing = program.getListing()
    COMMENT_PRE = 1
    call_to_addr_repr = ""
    func = get_function_containing(program, call_to_addr)
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
    refman = program.getReferenceManager()
    refman.addReference(ref_impl)

