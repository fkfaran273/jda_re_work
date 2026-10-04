"""Pass 10: decode MOVZ/MOVK immediates in libsigner.so around the constant
regions; find PCs of KB/IV2/K words and dump neighborhood immediates."""
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

SO = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
data = open(SO, "rb").read()

def decode_insn(word, pc):
    """Decode MOVZ/MOVK 32-bit; return (kind, imm16, hw, rd) or None."""
    if (word >> 23) == 0b10100101:  # 0x52800000 mask top: movz 32-bit
        pass
    op = word & 0x7F800000
    if (word & 0x7F800000) == 0x52800000:
        hw = (word >> 21) & 3
        imm16 = (word >> 5) & 0xFFFF
        rd = word & 31
        return ("MOVZ", imm16, hw, rd)
    if (word & 0x7F800000) == 0x72800000:
        hw = (word >> 21) & 3
        imm16 = (word >> 5) & 0xFFFF
        rd = word & 31
        return ("MOVK", imm16, hw, rd)
    return None

# scan every 4-byte word, record movz/movk
insns = {}
n = len(data) // 4
for i in range(n):
    w = struct.unpack_from("<I", data, 4 * i)[0]
    d = decode_insn(w, 4 * i)
    if d: insns[4 * i] = d
print(f"total movz/movk 32-bit insns: {len(insns)}")

# reconstruct 32-bit constants: MOVZ hw=0 followed (within a few insns) by
# MOVK hw=1 same rd
consts = {}  # pc -> value
pcs = sorted(insns)
for idx, pc in enumerate(pcs):
    kind, imm, hw, rd = insns[pc]
    if kind == "MOVZ" and hw == 0:
        # look ahead up to 8 insns for MOVK hw=1 same rd
        for pc2 in pcs[idx + 1: idx + 9]:
            kind2, imm2, hw2, rd2 = insns[pc2]
            if rd2 == rd and kind2 == "MOVZ": break
            if rd2 == rd and kind2 == "MOVK" and hw2 == 1:
                consts[pc] = imm | (imm2 << 16)
                break
            if rd2 != rd and kind2 == "MOVK": break
print(f"reconstructed 32-bit constants: {len(consts)}")

# find KB words (BE and LE)
KB_be = [int.from_bytes(KB[4*i:4*i+4], "big") for i in range(60)]
KB_le = [int.from_bytes(KB[4*i:4*i+4], "little") for i in range(60)]
IV2_le = [int.from_bytes(IV2[4*i:4*i+4], "little") for i in range(8)]
IV2_be = [int.from_bytes(IV2[4*i:4*i+4], "big") for i in range(8)]
K_le = [int.from_bytes(K[4*i:4*i+4], "little") for i in range(8)]
K_be = [int.from_bytes(K[4*i:4*i+4], "big") for i in range(8)]

def find_word(val):
    return sorted(pc for pc, v in consts.items() if v == val)

for name, arr in (("KB_be", KB_be), ("KB_le", KB_le), ("IV2_le", IV2_le),
                  ("IV2_be", IV2_be), ("K_le", K_le), ("K_be", K_be)):
    pcs_found = [find_word(v) for v in arr]
    nfound = sum(1 for p in pcs_found if p)
    print(f"{name}: {nfound}/{len(arr)} words found as immediates")
    if nfound:
        ex = [(i, [hex(x) for x in p]) for i, p in enumerate(pcs_found) if p][:4]
        print(f"   first: {ex}")

# dump immediate neighborhoods around KB region
kb_pcs = sorted(pc for pc, v in consts.items()
                if v in set(KB_be) or v in set(KB_le))
if kb_pcs:
    lo, hi = min(kb_pcs), max(kb_pcs)
    print(f"\nKB immediate PCs span: {hex(lo)} .. {hex(hi)}")
    # neighborhood: all constants within +/- 0x400
    near = [pc for pc in pcs if lo - 0x400 <= pc <= hi + 0x400]
    print(f"constants near KB region ({len(near)}):")
    for pc in near:
        v = consts.get(pc)
        tag = ""
        if v in KB_be: tag = f" ==KB_be[{KB_be.index(v)}]"
        if v in KB_le: tag += f" ==KB_le[{KB_le.index(v)}]"
        print(f"  {hex(pc)}: {v:08x}{tag}")
