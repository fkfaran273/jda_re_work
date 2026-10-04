"""Pass 10b: raw 16-bit immediate halves in the KB and K/IV2 regions."""
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

SO = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
data = open(SO, "rb").read()

def decode(word):
    if (word & 0x7F800000) == 0x52800000:
        return ("MOVZ", (word >> 21) & 3, (word >> 5) & 0xFFFF, word & 31)
    if (word & 0x7F800000) == 0x72800000:
        return ("MOVK", (word >> 21) & 3, (word >> 5) & 0xFFFF, word & 31)
    return None

def dump_region(lo, hi, label, kb_halves_be, kb_halves_le):
    print(f"===== {label}: {hex(lo)}..{hex(hi)} =====")
    seq = []
    for pc in range(lo, hi, 4):
        w = struct.unpack_from("<I", data, pc)[0]
        d = decode(w)
        if d:
            seq.append((pc, d))
    # match KB 16-bit halves
    kbset_be = set(kb_halves_be); kbset_le = set(kb_halves_le)
    hits = 0
    for pc, (k, hw, imm, rd) in seq:
        tag = ""
        if imm in kbset_be or imm in kbset_le:
            tag = "  <-- KB half"
            hits += 1
        print(f"  {hex(pc)}: {k} w{rd}, #{imm:04x} lsl #{16*hw}{tag}")
    print(f"  ({len(seq)} movz/movk, {hits} KB-half hits)")
    return seq

KB_be_halves = [int.from_bytes(KB[2*i:2*i+2], "big") for i in range(120)]
KB_le_halves = [int.from_bytes(KB[2*i:2*i+2], "little") for i in range(120)]

# KB region stated in the task
dump_region(0x119b00, 0x119c80, "KB region start", KB_be_halves, KB_le_halves)
print()
dump_region(0x1061c0, 0x106320, "K region", [], [])
