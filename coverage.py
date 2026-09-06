#@runtime Jython
#@description coverage measurement for an estimation of reversing completeness
from __main__ import *
import json
import sys
from ghidra.program.model.data import StringDataType, AbstractStringDataType, DefaultDataType, Undefined
from ghidra.program.model.address import AddressSet

from ghidra_api._compat import resolve_program, resolve_monitor, get_memory_blocks, get_bytes
from ghidra_api.decomp_utils import DecompUtils

PADDING_BYTES = set([0, 0xff, 0xcc, 0x90])


def _is_default_type(dt):
    if dt is None:
        return True
    name = dt.getName()
    if isinstance(dt, DefaultDataType):
        return True
    if isinstance(dt, Undefined):
        return True
    if name.startswith("undefined"):
        return True
    return False


def _is_void_type(dt):
    if dt is None:
        return False
    return dt.getName() == "void"


def _is_string_data(data):
    if data is None:
        return False
    dt = data.getDataType()
    if isinstance(dt, AbstractStringDataType):
        return True
    name = dt.getName().lower()
    return "string" in name


def measure_byte_coverage(program=None):
    program = resolve_program(program)
    listing = program.getListing()
    fm = program.getFunctionManager()

    func_body = AddressSet()
    for func in fm.getFunctions(True):
        if func.isExternal():
            continue
        func_body.add(func.getBody())
    total = 0
    code = 0
    data = 0
    string = 0
    padding = 0

    for block in get_memory_blocks(program):
        if not block.isInitialized():
            continue
        start = block.getStart()
        size = block.getSize()
        total += size

        CHUNK_SIZE = 4096
        chunk_raw = None
        chunk_offset_base = 0

        addr = start
        end = block.getEnd()
        while addr is not None and addr.compareTo(end) <= 0:
            if func_body.contains(addr):
                instr = listing.getInstructionContaining(addr)
                if instr is not None:
                    instr_len = instr.getLength()
                    code += instr_len
                    addr = addr.add(instr_len)
                    continue

            defined_data = listing.getDefinedDataContaining(addr)
            if defined_data is not None and defined_data.getAddress().compareTo(addr) <= 0:
                data_len = defined_data.getLength()
                if _is_string_data(defined_data):
                    string += data_len
                else:
                    data += data_len
                next_addr = defined_data.getAddress().add(data_len)
                if next_addr.compareTo(addr) <= 0:
                    addr = addr.add(1)
                else:
                    addr = next_addr
                continue

            block_offset = addr.subtract(start)
            if chunk_raw is None or block_offset < chunk_offset_base or block_offset >= chunk_offset_base + len(chunk_raw):
                chunk_offset_base = block_offset
                remaining = size - block_offset
                read_size = min(CHUNK_SIZE, remaining)
                if read_size > 0:
                    chunk_raw = bytearray(get_bytes(program, addr, read_size))
                else:
                    chunk_raw = bytearray()

            local_offset = block_offset - chunk_offset_base
            if 0 <= local_offset < len(chunk_raw):
                byte_val = chunk_raw[local_offset] & 0xff
            else:
                byte_val = -1

            if byte_val in PADDING_BYTES:
                padding += 1
            addr = addr.add(1)

    undef = total - code - data - string - padding
    if undef < 0:
        undef = 0
    return {
        "total": total,
        "code": code,
        "data": data,
        "str": string,
        "pad": padding,
        "undef": undef
    }


def measure_function_naming(program=None):
    program = resolve_program(program)
    fm = program.getFunctionManager()
    total_funcs = 0
    named = 0

    for func in fm.getFunctions(True):
        if func.isThunk() or func.isExternal():
            continue
        total_funcs += 1
        name = func.getName()
        if (not name.startswith("FUN_") and not name.startswith("thunk_FUN_") and name not in ("", "entry")):
            named += 1
    return {"funcs": total_funcs, "named": named}


def measure_typing_coverage(program=None):
    program = resolve_program(program)
    fm = program.getFunctionManager()

    params_total = 0
    params_typed = 0
    returns_total = 0
    returns_typed = 0
    returns_void = 0
    returns_default = 0
    locals_total = 0
    locals_typed = 0

    du = DecompUtils(program=program)
    count = 0

    # NOTE: I think there is a better way to do this that doesn't involve decompiling every function
    for func in fm.getFunctions(True):
        if func.isThunk() or func.isExternal():
            continue
        returns_total += 1
        ret_type = func.getReturnType()
        if _is_void_type(ret_type):
            returns_void += 1
        elif _is_default_type(ret_type):
            returns_default += 1
        else:
            returns_typed += 1

        sig = func.getSignature()
        args = list(sig.getArgument())
        params_total += len(args)
        for arg in args:
            dt = arg.getDataType()
            if not _is_default_type(dt):
                params_typed += 1

        count += 1
        try:
            hf = du.get_high_function(func)
            if hf is not None:
                local_sym_map = hf.getLocalSymbolMap()
                for sym in local_sym_map.getSymbols():
                    if sym.isParameter():
                        continue
                    locals_total += 1
                    dt = sym.getDataType()
                    if not _is_default_type(dt):
                        locals_typed += 1
        except Exception:
            print("failed to get typed locals for %s" % func.name)

    return {
        "params_total": params_total,
        "params_typed": params_typed,
        "returns_total":returns_total,
        "returns_typed": returns_typed,
        "returns_void": returns_void,
        "returns_default":returns_default,
        "locals_total": locals_total,
        "locals_typed": locals_typed,
    }


def measure_globals(program=None):
    program = resolve_program(program)
    listing = program.getListing()

    global_total = 0
    globals_named = 0
    globals_typed = 0

    for block in get_memory_blocks(program):
        if not block.isInitialized():
            continue
        if block.isExecute() and not block.isWrite():
            continue
        data_iter = listing.getDefinedData(block.getAddressRange(), True)
        while data_iter.hasNext():
            data = data_iter.next()
            globals_total += 1
            label = data.getLabel()
            if label is not None:
                if (not label.startswith("DAT_")
                    and not label.startswith("s_")
                    and not label.startswith("addr_")):
                    globals_named += 1

            dt = data.getDataType()
            if not _is_default_type(dt) and not _is_string_data(data):
                globals_typed += 1

    return {
        "globals_total": globals_total,
        "globals_named": globals_named,
        "globals_typed": globals_typed,
    }



