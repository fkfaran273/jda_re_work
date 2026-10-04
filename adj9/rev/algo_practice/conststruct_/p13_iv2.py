"""Pass 13: find IV2 halves as any movz/movk immediates; verify KB array tail
encoding; dump before-K and after-KB regions."""
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

IV2_be16 = [int.from_bytes(IV2[2*i:2*i+2], "big") for i in range(16)]
IV2_le16 = [int.from_bytes(IV2[2*i:2*i+2], "little") for i in range(16)]
K_be16 = [int.from_bytes(K[2*i:2*i+2], "big") for i in range(16)]

targets = {}
for i, v in enumerate(IV2_be16): targets.setdefault(v, []).append(f"IV2be[{i}]")
for i, v in enumerate(IV2_le16): targets.setdefault(v, []).append(f"IV2le[{i}]")
for i, v in enumerate(K_be16): targets.setdefault(v, []).append(f"Kbe[{i}]")
for i, v in enumerate(K_le16 if False else [int.from_bytes(K[2*i:2*i+2], "little") for i in range(16)]):
    targets.setdefault(v, []).append(f"Kle[{i}]")

print("== all movz/movk whose imm16 is an IV2/K 16-bit half ==")
hits = []
for pc in range(0, len(data) - 4, 4):
    w = struct.unpack_from("<I", data, pc)[0]
    d = decode(w)
    if d and d[2] in targets:
        hits.append((pc, d[0], d[1], d[2], d[3], targets[d[2]]))
for pc, k, hw, imm, rd, tags in hits:
    print(f"  {hex(pc)}: {k} w{rd} #{imm:04x} lsl#{16*hw}  {','.join(tags)}")

print("\n== KB array tail 0x11c7f0..0x11c8d0 raw ==")
for pc in range(0x11c7f0, 0x11c8d0, 4):
    w = struct.unpack_from("<I", data, pc)[0]
    d = decode(w)
    if d:
        print(f"  {hex(pc)}: {d[0]} w{d[3]} #{d[2]:04x} lsl#{16*d[1]}")
    else:
        print(f"  {hex(pc)}: {w:08x}")

print("\n== region before K: 0x106000..0x1061e4 (movz/movk) ==")
for pc in range(0x106000, 0x1061e4, 4):
    w = struct.unpack_from("<I", data, pc)[0]
    d = decode(w)
    if d:
        print(f"  {hex(pc)}: {d[0]} w{d[3]} #{d[2]:04x} lsl#{16*d[1]}")
