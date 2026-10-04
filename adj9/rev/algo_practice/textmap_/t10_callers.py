"""t10 -- fix caller attribution; plt disasm; 0x13f434; cluster summaries."""
import struct, json, bisect
import capstone
from collections import defaultdict, Counter

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fstarts = [f[0] for f in fdes]
fsize = {f[0]: f[1] for f in fdes}
feat = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/feat.json"))
edges = [(a, b) for a, b in json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/edges.json"))["edges"]]

def func_of(a):
    i = bisect.bisect_right(fstarts, a) - 1
    if i >= 0 and fstarts[i] <= a < fstarts[i] + fsize[fstarts[i]]:
        return fstarts[i]
    return None
def region(a):
    if a < 0x99000: return 'R1'
    if a < 0xBCA30: return 'M1'
    if a < 0x100094: return 'R2'
    if a < 0x12AA48: return 'M2'
    if a < 0x146000: return 'R3'
    return 'M3'

callers = defaultdict(set); callees = defaultdict(set)
midbl = defaultdict(set)
for site, tgt in edges:
    f = func_of(site)
    if f is None: continue
    if tgt in fsize:
        callees[f].add(tgt); callers[tgt].add(f)
    else:
        midbl[f].add(tgt)

for s in (0x148414, 0x1488e4, 0x12cb74, 0xda97c, 0xdb1cc, 0x13f434, 0x6f990, 0x81008, 0x51780,
          0x3c178, 0x8d6f4, 0x3348c, 0xeb6f8, 0x97414, 0x2c594, 0x1400cc, 0x13ef40, 0x13f7a4,
          0xd0838, 0xd505c, 0xd417c, 0xcc39c, 0x95fc4, 0xe2be0, 0xbb548, 0xffb08, 0x1441e4, 0x15544, 0x8c00):
    cl = [hex(x) for x in sorted(callers.get(s, ()))]
    ce = [hex(x) for x in sorted(callees.get(s, ()))]
    print("%s (%s,%dB) ncallers=%d %s" % (hex(s), region(s), fsize.get(s, -1), len(cl), cl[:8]))
    if ce: print("     callees(%d): %s" % (len(ce), ce[:14]))

# how many functions are called ONLY via mid-function bl or via DRR/indirect?
nobl = [f for f in fsize if not callers.get(f)]
print("\nfunctions never directly called:", len(nobl), "of", len(fsize))
byreg = Counter(region(f) for f in nobl)
print("  by region:", dict(sorted(byreg.items())))
big = sorted((f for f in nobl), key=lambda f: -fsize[f])[:25]
print("  largest never-called:", [(hex(f), fsize[f], region(f)) for f in big])

# ---- .plt full disasm
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
print("\n=== .plt 0x1489c0-0x1489f8 (first stubs) ===")
for ins in md.disasm(d[0x1489c0:0x1489c0+0x60], 0x1489c0):
    print("  %08x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))

# ---- 0x8c00 area (what is adr x0, 0x8c00 pointing at?)
print("\n=== 0x8bf0-0x8c98 ===")
for ins in md.disasm(d[0x8bf0:0x8c98], 0x8bf0):
    print("  %08x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))

# DRR index usage: 0x13f434 disasm head
import io
buf = io.StringIO()
def dis(s, out, maxn=None):
    z = fsize[s]
    print("\n=== %s (%s, %d bytes) ===" % (hex(s), region(s), z), file=out)
    adrpv = {}
    n = 0
    for ins in md.disasm(d[s:s+z], s):
        m, ops = ins.mnemonic, ins.op_str
        note = ""
        if m == 'adrp':
            r, pg = ops.split(', '); adrpv[r] = int(pg.lstrip('#'), 0)
        elif m == 'bl':
            t = int(ops.lstrip('#'), 0)
            note = "  ; -> " + hex(t)
        elif m.startswith('ldr') or m.startswith('str'):
            b = ops.find('[')
            if b != -1 and adrpv:
                inner = ops[b+1:ops.find(']')].split(',')
                base = inner[0].strip()
                if base in adrpv:
                    off = int(inner[1].strip().lstrip('#'), 0) if len(inner) > 1 else 0
                    note = "  ; ABS 0x%x" % (adrpv[base] + off)
        print("  %08x: %-8s %-40s%s" % (ins.address, m, ops, note), file=out)
        n += 1
        if maxn and n >= maxn:
            print("  ...", file=out); break
dis(0x13f434, buf, 90)
print(buf.getvalue())
