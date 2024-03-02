
from __main__ import *


def getStackRegister(program=None):
    if program is None:
        program = currentProgram
    return program.getCompilerSpec().getStackPointer()


def getAllContainedRegisters(reg):
    to_visit = set([reg])
    visited = set()
    while to_visit:
        r = to_visit.pop()
        for child in r.getChildRegisters():
            if child is None:
                continue
            if child in to_visit:
                continue
            if child in visited:
                continue
            if child == r:
                continue
            to_visit.add(child)
        visited.add(r)
    return visited


def getGeneralPurposeRegsToParamMapForCallingConvention(cc, program=None):
    """
    Create a map of general purpose registers to parameter number for
    the provided calling convention and program
    """
    if program is None:
        program = currentProgram
    inp_storage_locs = cc.getPotentialInputRegisterStorage(program)
    gpr_storage_locs = []
    # get all of the non-vector storage locations
    for stor in inp_storage_locs:
        storage_registers = stor.getRegisters()
        for reg in storage_registers:
            base_reg = reg.getBaseRegister()
            if base_reg.isVectorRegister() is True:
                continue
            gpr_storage_locs.append(base_reg)
    # map all of the general purpose registers to the parameter that they
    # should fit into
    reg_to_param = {}
    for ind, base_reg in enumerate(gpr_storage_locs):
        for r in getAllContainedRegisters(base_reg):
            reg_to_param[r] = ind+1
    return reg_to_param


GPR_TO_PARAM_MAP_CACHE = {}


def getRegToParamMapForFunc(func):
    """
    Get a map of {general_purpose_register: int(param_num)} for the given
    function
    """
    cc = func.getCallingConvention()
    program = func.getProgram()
    key = (cc, program)
    maybe_res = GPR_TO_PARAM_MAP_CACHE.get(key)
    if maybe_res is None:
        maybe_res = getGeneralPurposeRegsToParamMapForCallingConvention(cc, program=program)
        GPR_TO_PARAM_MAP_CACHE[key] = maybe_res
    return maybe_res
