"""Pass 11: full decode of the VM array-literal encoding.

From the KB slice:  MOVZ w2,#0x00VV (value) ... MOVZ w2,#0x0100|idx (index)
Looks like each byte = (value, 0x01NN) pair, 6 insns apart.
Dump raw insns for 2 KB bytes to learn the exact layout, then scan the whole
file for array literals: runs of alternating 0x01NN / 0x00VV MOVZ w2.
"""
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

SO = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
data = open(SO, "rb").read()

NAMES = {0x52800000: "MOVZ", 0x72800000: "MOVK"}

def decode(word):
    top = word & 0x7F800000
    if top == 0x52800000:
        return ("MOVZ", (word >> 21) & 3, (word >> 5) & 0xFFFF, word & 31)
    if top == 0x72800000:
        return ("MOVK", (word >> 21) & 3, (word >> 5) & 0xFFFF, word & 31)
    if (word >> 24) == 0x52:
        return ("MOVZ64", (word >> 21) & 3, (word >> 5) & 0xFFFF, word & 31)
    return None

print("== raw insn dump 0x119ba0..0x119c30 ==")
for pc in range(0x119ba0, 0x119c30, 4):
    w = struct.unpack_from("<I", data, pc)[0]
    d = decode(w)
    if d:
        k, hw, imm, rd = d
        print(f"  {hex(pc)}: {k} w{rd}, #{imm:04x} lsl #{16*hw}")
    else:
        print(f"  {hex(pc)}: {w:08x}  (other)")

# scan whole file: MOVZ w2 imm16 sequence with pcs
seq = []
for pc in range(0, len(data) - 4, 4):
    w = struct.unpack_from("<I", data, pc)[0]
    d = decode(w)
    if d and d[0] == "MOVZ" and d[1] == 0:  # MOVZ hw=0
        seq.append((pc, d[2], d[3]))

# array-literal pattern: ... 0x0100|idx, 0x00VV, 0x0100|idx+1, 0x00VV ...
# from the dump: value THEN index: #0043, #0101, #00fc, #0102 -> value V then
# 0x01NN where NN = next index.  Extract pairs (pc, NN, V).
lits = []  # (pc_of_value, index_implied, value)
for i in range(1, len(seq)):
    pc, imm, rd = seq[i]
    if 0x0100 <= imm <= 0x02FF:
        idx = imm & 0xFF
        opc = imm >> 8
        pcv, immv, rdv = seq[i - 1]
        if immv <= 0xFF and rdv == rd:
            lits.append((pcv, opc, idx, immv))

print(f"\ntotal (value,index) literal pairs: {len(lits)}")
# group into runs by contiguity of index and pc distance
runs = []
cur = []
for j in range(len(lits)):
    if j == 0:
        cur = [lits[j]]; continue
    pcv, opc, idx, v = lits[j]
    pp, po, pi, pv = lits[j - 1]
    if idx == (pi + 1) & 0xFF and opc == po and 0 < pcv - pp < 0x40:
        cur.append(lits[j])
    else:
        if len(cur) >= 4: runs.append(cur)
        cur = [lits[j]]
if len(cur) >= 4: runs.append(cur)
print(f"contiguous literal runs (>=4): {len(runs)}")
for r in runs:
    opc = r[0][1]
    vals = bytes(v for _, _, _, v in r)
    print(f"  opcode 0x{opc:02x} idx {r[0][2]}..{r[-1][2]} pc {hex(r[0][0])}.."
          f"{hex(r[-1][0])} len {len(r)}: {vals[:40].hex()}{'...' if len(r)>40 else ''}")

# check KB as literal: KB[0]=43, KB[1]=fc...
kb_run = None
for r in runs:
    vals = bytes(v for _, _, _, v in r)
    if vals == KB[:len(vals)] and len(vals) >= 16:
        kb_run = r
        print(f"\nKB found as literal run: pc {hex(r[0][0])}..{hex(r[-1][0])} "
              f"len {len(r)} (KB len 240)")
# IV2 / K as literal
for name, blob in (("IV2", IV2), ("K", K)):
    for r in runs:
        vals = bytes(v for _, _, _, v in r)
        if blob[:len(vals)] == vals and len(vals) >= 8:
            print(f"{name} prefix found as literal: {hex(r[0][0])} len {len(r)}")
