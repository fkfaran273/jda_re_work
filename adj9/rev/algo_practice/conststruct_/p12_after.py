"""Pass 12: dump the region after the KB literal; search for IV2 and an
F-table in (value,index) literal encoding anywhere in the file."""
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

SO = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
data = open(SO, "rb").read()

def decode(word):
    top = word & 0x7F800000
    if top == 0x52800000:
        return ("MOVZ", (word >> 21) & 3, (word >> 5) & 0xFFFF, word & 31)
    if top == 0x72800000:
        return ("MOVK", (word >> 21) & 3, (word >> 5) & 0xFFFF, word & 31)
    return None

# all MOVZ hw=0 imm<=0xFF or imm 0x0100..0x02FF, any rd
seq = []
for pc in range(0, len(data) - 4, 4):
    w = struct.unpack_from("<I", data, pc)[0]
    d = decode(w)
    if d and d[0] == "MOVZ" and d[1] == 0:
        seq.append((pc, d[2], d[3]))

def find_pattern(vals, idxs, window=0x60):
    """find consecutive MOVZ literals matching alternating value/index."""
    res = []
    for i in range(len(seq) - len(vals) * 2):
        ok = True
        pcs = []
        for k, (v, ix) in enumerate(zip(vals, idxs)):
            p1, imm1, rd1 = seq[i + 2 * k]
            p2, imm2, rd2 = seq[i + 2 * k + 1]
            if not (imm1 == 0x00 + v and imm2 == 0x0100 + ix and rd1 == rd2):
                ok = False; break
            if k and p1 - seq[i + 2 * k - 1][0] > window: ok = False; break
            pcs.append(p1)
        if ok:
            res.append(pcs[0])
    return res

# IV2 first bytes: eb a2 c4 35 0f 40 02 dc
pat = find_pattern([0xeb, 0xa2, 0xc4, 0x35], [0, 1, 2, 3])
print("IV2 as (val,idx) literal:", [hex(x) for x in pat])
# IV2 BE word halves? EB A2 = 0xeba2 word: search movz/movk word 0xe6a2...?
# K full: dump 0x1061c0..0x106800
print("\n== K region full dump 0x1061e0..0x106800 (MOVZ/MOVK only) ==")
for pc in range(0x1061e0, 0x106800, 4):
    w = struct.unpack_from("<I", data, pc)[0]
    d = decode(w)
    if d:
        k, hw, imm, rd = d
        print(f"  {hex(pc)}: {k} w{rd} #{imm:04x} lsl#{16*hw}")

# F-table probe: T[0x8a]=0x14, T[0x8b]=0x96 adjacent indices
patF = find_pattern([0x14, 0x96], [0x8a, 0x8b])
print("\nF-table (idx 8a,8b) literal:", [hex(x) for x in patF])
# other adjacent known pairs: (d4->d8, d6->3a no), (14->97 at 14 only)...
# known F with adjacent indices: 8a/8b only.
# try also with index-first encoding: #0x018a, #0x0014, #0x018b, #0x0096
res = []
for i in range(len(seq) - 4):
    if (seq[i][1] == 0x018a and seq[i+1][1] == 0x0014 and
            seq[i+2][1] == 0x018b and seq[i+3][1] == 0x0096):
        res.append(seq[i][0])
print("F-table (idx-first):", [hex(x) for x in res])

# dump 0x11c888..0x11d800: what follows KB
print("\n== after KB literal: 0x11c888..0x11d200 (MOVZ/MOVK) ==")
for pc in range(0x11c888, 0x11d200, 4):
    w = struct.unpack_from("<I", data, pc)[0]
    d = decode(w)
    if d:
        k, hw, imm, rd = d
        print(f"  {hex(pc)}: {k} w{rd} #{imm:04x} lsl#{16*hw}")
