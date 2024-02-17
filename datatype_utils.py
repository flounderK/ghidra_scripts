
from __main__ import *
from ghidra.program.database.data import DataTypeUtilities
from ghidra.program.model.data import PointerDataType


def find_datatypes_using(datatype, check_full_chains=True):
    initial_dt = datatype
    visited = set()
    to_visit = set([datatype])
    while to_visit:
        curr_dt = to_visit.pop()
        for parent_dt in curr_dt.getParents():
            base = DataTypeUtilities.getBaseDataType(parent_dt)
            if base != initial_dt:
                # not a (series)? of pointer/array to the data type
                if check_full_chains is False:
                    continue
            if parent_dt in visited:
                continue
            if parent_dt in to_visit:
                continue
            if parent_dt == curr_dt:
                continue
            to_visit.add(parent_dt)
        visited.add(curr_dt)
    return visited


def getUndefinedRegisterSizeDatatype(program=None):
    """
    Returns an "undefined*" datatype that is the appropriate 
    size to hold a pointer. Useful if you don't know the real datatype 
    and expect it to have to be changed later
    """
    if program is None:
        program = currentProgram
    dtm = program.getDataTypeManager()
    # this might not work for older versions of ghidra
    default_ptr_size = program.getDefaultPointerSize()
    return dtm.getDataType("/undefined%d" % default_ptr_size)


def getGenericPointerDatatype():
    return PointerDataType()