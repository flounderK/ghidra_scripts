
from __main__ import *
from ghidra.program.database.data import DataTypeUtilities
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import MetaDataType
from ghidra.program.model.data import EnumDataType


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
    default_ptr_size = program.getDefaultPointerSize()
    return dtm.getDataType("/undefined%d" % default_ptr_size)


def getGenericPointerDatatype():
    return PointerDataType()


def getVoidPointerDatatype(program=None):
    if program is None:
        program = currentProgram
    dtm = program.getDataTypeManager()
    void_dt = dtm.getDataType("/void")
    return dtm.getPointer(void_dt)


def areBaseDataTypesEquallyUnique(datatype_a, datatype_b):
    datatype_a = DataTypeUtilities.getBaseDataType(datatype_a)
    datatype_b = DataTypeUtilities.getBaseDataType(datatype_b)
    a_meta = MetaDataType.getMeta(datatype_a)
    b_meta = MetaDataType.getMeta(datatype_b)
    return a_meta.compareTo(b_meta) == 0

def applyDataTypeAtAddress(address, datatype, size=None, program=None):
    if program is None:
        program = currentProgram
    if size is None:
        size = datatype.getLength()
    listing = program.getListing()
    listing.clearCodeUnits(address, address.add(size-1), False)
    listing.createData(address, datatype, size)


def get_all_sub_components_of_datadb(datadb):
    initial_db = datadb
    visited = set()
    to_visit = set([datadb])
    while to_visit:
        curr_db = to_visit.pop()
        for ind in range(curr_db.getNumComponents()):
            comp = curr_db.getComponent(ind)
            if comp == initial_db:
                continue
            if comp in visited:
                continue
            if comp in to_visit:
                continue
            if comp == curr_db:
                continue
            to_visit.add(comp)
        visited.add(curr_db)
    return visited


def get_all_defined_datatype_instances(dt):
    using_dt_set = find_datatypes_using(dt)
    listing = currentProgram.getListing()
    dats = [i for i in listing.getDefinedData(1) if hasattr(i, "dataType") and i.dataType in using_dt_set]
    instances = []
    for dat in dats:
        if hasattr(dat, "isPointer") and dat.isPointer() is True:
            continue
        matching_comps = [comp for comp in get_all_sub_components_of_datadb(dat) if hasattr(comp, "dataType") and comp.dataType == dt]
        instances.extend(matching_comps)
    return instances

