"""t6 -- hexdump rodata; robust caller chains; disasm key small fns."""
import struct, json
from collections import defaultdict

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()

print("=== .rodata hexdump (0x3560-0x36b0) ===")
for off in range(0x3560, 0x36b0, 16):
    row = d[off:off+16]
    print("  %04x: %s  |%s|" % (off, row.hex(' '), ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)))

feat = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/feat.json"))
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fend = {f[0]: f[0]+f[1] for f in fdes}
fsize = {f[0]: f[1] for f in fdes}

def region(a):
    if a < 0x99000: return 'R1'
    if a < 0xBCA30: return 'M1'
    if a < 0x100094: return 'R2'
    if a < 0x12AA48: return 'M2'
    if a < 0x146000: return 'R3'
    return 'M3'

callers = defaultdict(set); callees = defaultdict(set)
for s, f in feat.items():
    si = int(s)
    for t in f['bl']:
        ti = int(t, 16)
        if ti in fend:
            callees[si].add(ti); callers[ti].add(si)

def upchain(t, depth=0, seen=None):
    if seen is None: seen = set()
    if t in seen or depth > 15: return
    seen.add(t)
    for c in sorted(callers.get(t, ())):
        print("  " + "  " * depth + "%s (region %s, size %d) -> %s" % (hex(c), region(c), fsize.get(c, -1), hex(t)))
        upchain(c, depth + 1, seen)

print("\n=== upward call chains ===")
for tgt in (0x12cb74, 0xdb1cc, 0xda4b0):
    print(" callers of %s:" % hex(tgt))
    upchain(tgt)

print("\n=== callees ===")
for f in (0xdb1cc, 0xda4b0, 0x12cb74, 0x100094):
    print(" %s -> %s" % (hex(f), [hex(c) for c in sorted(callees.get(f, ()))])[:400])

# disassemble a few small functions fully
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
def dis(s, limit=None):
    z = fsize[s]
    print("\n--- %s (region %s, %d bytes) ---" % (hex(s), region(s), z))
    n = 0
    for ins in md.disasm(d[s:s+z], s):
        print("  %08x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
        n += 1
        if limit and n >= limit:
            print("  ...")
            break

for s in (0x12e5f4,):
    dis(s)
