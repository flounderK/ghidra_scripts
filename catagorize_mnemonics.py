# just a hacky script to measure some properties of instructions in the binary 
# to help decide which scalar mask to use for large scalar searches
from __main__ import *
from ghidra.program.model.lang import OperandType
from collections import defaultdict


def operand_type_str(op_type):
    valstrs = []
    if op_type & OperandType.ADDRESS:
        valstrs.append("ADDRESS")
    if op_type & OperandType.BIT:
        valstrs.append("BIT")
    if op_type & OperandType.BYTE:
        valstrs.append("BYTE")
    if op_type & OperandType.CODE:
        valstrs.append("CODE")
    if op_type & OperandType.COP:
        valstrs.append("COP")
    if op_type & OperandType.DATA:
        valstrs.append("DATA")
    if op_type & OperandType.DYNAMIC:
        valstrs.append("DYNAMIC")
    if op_type & OperandType.FLAG:
        valstrs.append("FLAG")
    if op_type & OperandType.FLOAT:
        valstrs.append("FLOAT")
    if op_type & OperandType.IMMEDIATE:
        valstrs.append("IMMEDIATE")
    if op_type & OperandType.IMPLICIT:
        valstrs.append("IMPLICIT")
    if op_type & OperandType.INDIRECT:
        valstrs.append("INDIRECT")
    if op_type & OperandType.LIST:
        valstrs.append("LIST")
    if op_type & OperandType.PORT:
        valstrs.append("PORT")
    if op_type & OperandType.QUADWORD:
        valstrs.append("QUADWORD")
    if op_type & OperandType.READ:
        valstrs.append("READ")
    if op_type & OperandType.REGISTER:
        valstrs.append("REGISTER")
    if op_type & OperandType.RELATIVE:
        valstrs.append("RELATIVE")
    if op_type & OperandType.SCALAR:
        valstrs.append("SCALAR")
    if op_type & OperandType.SIGNED:
        valstrs.append("SIGNED")
    if op_type & OperandType.TEXT:
        valstrs.append("TEXT")
    if op_type & OperandType.WORD:
        valstrs.append("WORD")
    if op_type & OperandType.WRITE:
        valstrs.append("WRITE")
    return "|".join(valstrs)



mnemonics = {}
for cu in currentProgram.getListing().getInstructions(1):
    # print(cu)
    mnen = cu.mnemonicString
    if mnen in mnemonics:
        continue
    if not hasattr(cu, "prototype"):
        continue
    prot = cu.prototype
    operand_infos = []
    any_values = False
    for ind in range(1, prot.numOperands):
        op_type = cu.getOperandType(ind)
        if OperandType.isScalar(op_type) or OperandType.isImmediate(op_type) or OperandType.isAddress(op_type):
            any_values = True
        else:
            continue
        op_mask = prot.getOperandValueMask(ind)
        operand_infos.append((op_type, op_mask))
    if not any_values:
        continue
    mnemonics[mnen] = operand_infos


type_count_d = defaultdict(lambda: 0)
mask_count_d = defaultdict(lambda: 0)
mask_to_type = defaultdict(set)
for typ, mask in sum(mnemonics.values(), []):
    mask_val = int(mask.toString(), 16)
    mask_count_d[mask_val] += 1
    type_count_d[typ] += 1
    mask_to_type[mask_val].add(typ)

print("\nmask frequency")
for k, v in mask_count_d.items():
    print("%#x: %d" % (k, v))

print("")
print("type frequency")
for typ, count in type_count_d.items():
    print("%#x: %s : %d" % (typ, operand_type_str(typ), count))

print("")
print("types seen for masks")
for mask, typs in mask_to_type.items():
    print("%#x" % mask)
    for typ in typs:
        print("%s" % operand_type_str(typ))
    print("")

    