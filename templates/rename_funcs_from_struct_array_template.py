from __main__ import *
from datatype_utils import get_all_defined_datatype_instances
from ghidra.program.model.symbol import SourceType
import struct

id_to_name_map = {0xf071: "CMD_A", 0x4511: "CMD_B"}

dtm = currentProgram.getDataTypeManager()
cmd_handler_dt = [i for i in dtm.getAllStructures() if i.name == '<cmd_handler_struct_name>'][0]

pack_end = ">" if currentProgram.getMemory().isBigEndian() else "<"
pack_code = pack_end + "H"
for inst in get_all_defined_datatype_instances(cmd_handler_dt):
    # need to manually unpack values to avoid java signedness issues
    cmd_id = struct.unpack(pack_code, inst.getComponentAt(0).getBytes())[0]
    handler_addr = inst.getComponentAt(4).value
    key = cmd_id
    maybe_new_name = id_to_name_map.get(key)
    if maybe_new_name is None:
        continue
    func = getFunctionContaining(handler_addr)
    if func is None:
        print("no func found at %s" % handler_addr)
        continue
    if not func.name.startswith("FUN_"):
        continue
    new_name = "%s_%s" % (maybe_new_name, str(func.entryPoint))
    print("renaming %s to %s" % (func.name, new_name))
    func.setName(new_name, SourceType.USER_DEFINED)
