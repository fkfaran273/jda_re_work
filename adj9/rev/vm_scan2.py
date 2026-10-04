import sys
sys.path.insert(0, '.')
from decryptors import LIB
import struct
elf = open(LIB, "rb").read()
def bl_target(word, pc):
    if (word >> 26) == 0x25:  # bl
        imm = word & 0x03FFFFFF
        if imm & 0x02000000: imm -= 0x04000000
        return (pc + (imm << 2)) & 0xFFFFFFFF
    return None
# text range guess 0x8d000..0x148d40 (plus 0x100000 region). scan whole file, validate va by file==va mapping? code VAs == file offsets here (dump_at uses elf[va:...])
targets = {}
for off in range(0x8000, len(elf)-4, 4):
    w = struct.unpack_from("<I", elf, off)[0]
    t = bl_target(w, off)
    if t is None: continue
    if 0x129000 <= t < 0x12aa48 or t in (0x147630,0x147734,0x146470,0x146ed8,0x147304,0x14784c,0x147a20,0x1472e8,0x146558,0x147c68):
        targets.setdefault(t, []).append(off)
for t in sorted(targets):
    cs = targets[t]
    print("target 0x%-6x : %3d callers  e.g. %s" % (t, len(cs), ", ".join("0x%x"%a for a in cs[:10])))
