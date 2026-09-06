#@runtime Jython
from __main__ import *
from ghidra.program.model.data import EnumDataType
from datatype_utils import get_all_defined_datatype_instances
import struct

pack_lookup = {
    1: "B",
    2: "H",
    4: "I",
    8: "Q"
}

new_enum_size = 4
listing = currentProgram.getListing()
dtm = currentProgram.getDataTypeManager()
struct_dt = [i for i in dtm.getAllStructures() if i.name == '<struct_name>'][0]
pack_end = ">" if currentProgram.getMemory().isBigEndian() else "<"
pack_code = pack_end + pack_lookup[new_enum_size]

new_enum = EnumDataType("<new_enum_name>", new_enum_size)

for inst in get_all_defined_datatype_instances(struct_dt):
    # need to manually unpack values to avoid java signedness issues
    val = struct.unpack(pack_code, inst.getComponentAt(0).getBytes())[0]
    string_addr = inst.getComponentAt(4).value
    if string_addr is None:
        continue
    if val == 0:
        continue

    def_dat = listing.getCodeUnitAt(string_addr)
    if def_dat is None:
        continue

    str_val = str(def_dat.value)
    if str_val == "":
        continue
    new_enum.add(str_val, val)


dtm.addDataType(new_enum, None)





