from __main__ import *
from pointer_utils import createPointerUtils, compile_byte_rexp_pattern
from ghidra.program.model.data import PointerDataType
import re
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


def applyDataTypeAtAddress(address, datatype, size=None, program=None):
    if program is None:
        program = currentProgram
    if size is None:
        size = datatype.getLength()
    listing = program.getListing()
    listing.clearCodeUnits(address, address.add(size), False)
    listing.createData(address, datatype, size)


def identify_unknown_pointers(program=None, align_to=4):
    if program is None:
        program = currentProgram
    dtm = program.getDataTypeManager()
    ptr_dt = [i for i in dtm.getAllDataTypes() if i.name == 'pointer'][0]
    pu = createPointerUtils(program=program)
    listing = program.getListing()
    patterns = []
    for m_block in getMemoryBlocks():
        start = m_block.start.getOffsetAsBigInteger()
        end = m_block.end.getOffsetAsBigInteger()
        pat = pu.generate_address_range_pattern(start, end)
        patterns.append(pat)
    full_pat = b'(%s)' % b'|'.join(patterns)
    rexp = compile_byte_rexp_pattern(full_pat)
    for addrs, m_objs in pu.search_memory_for_rexp(rexp, False):
        for addr in addrs:
            if addr.getOffsetAsBigInteger() % align_to != 0:
                continue
            def_code = listing.getCodeUnitContaining(addr)
            if def_code is not None:
                log.warning("match in code at %s" % addr)
                continue

            def_dat = listing.getDataContaining(addr)
            # skip defined data
            if def_dat is not None:
                continue
            log.info("found data at %s" % addr)
            applyDataTypeAtAddress(addr, ptr_dt)


identify_unknown_pointers()
