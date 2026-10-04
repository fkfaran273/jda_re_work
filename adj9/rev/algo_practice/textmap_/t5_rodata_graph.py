"""t5_rodata_graph.py -- rodata strings, call graph, chain to VM, giant fn profiles."""
import struct, json, bisect
from collections import defaultdict, Counter

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()

# ---- .rodata strings
print("=== .rodata (0x3560-0x36b0) ===")
ro = d[0x3560:0x36b0]
i = 0
while i < len(ro):
    j = ro.find(b'\0', i)
    if j == -1: j = len(ro)
    s = ro[i:j]
    if s:
        print("  0x%04x: %r" % (0x3560 + i, s))
    i = j + 1
# non-string tail
print("  raw tail bytes 0x3694-0x36b0:", d[0x3694:0x36b0].hex())

feat = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/feat.json"))
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fstarts = [f[0] for f in fdes]
fend = {f[0]: f[0]+f[1] for f in fdes}

def region(a):
    if a < 0x99000: return 'R1'
    if a < 0xBCA30: return 'M1'
    if a < 0x100094: return 'R2'
    if a < 0x12AA48: return 'M2'
    if a < 0x146000: return 'R3'
    return 'M3'

# ---- call graph (bl edges whose target is a function start)
callers = defaultdict(set); callees = defaultdict(set)
mid_bl = defaultdict(list)
for s, f in feat.items():
    for t in f['bl']:
        ti = int(t, 16)
        if ti in fend:
            callees[s].add(ti); callers[ti].add(s)
        else:
            mid_bl[s].append(ti)

# chain from JNI entries
def chain(start, depth=0, seen=None, out=None):
    if seen is None: seen = set()
    if out is None: out = []
    if start in seen or depth > 12: return out
    seen.add(start)
    for c in sorted(callees.get(start, ())):
        out.append((depth, start, c))
        chain(c, depth+1, seen, out)
    return out

print("\n=== call graph: who calls the VM launcher 0x12cb74 (recursively up) ===")
def upchain(t, depth=0, seen=None):
    if seen is None: seen = set()
    if t in seen or depth > 15: return
    seen.add(t)
    for c in sorted(callers.get(t, ())):
        print("  " + "  "*depth + "%s (%s,%d) -> %s" % (hex(c), region(c), feat[str(c)]['size'] if str(c) in feat else -1, hex(t)))
        upchain(c, depth+1, seen)
upchain(0x12cb74)
upchain(0xdb1cc)
upchain(0xda4b0)

print("\n=== callees of VM launcher 0x12cb74 ===")
print([hex(c) for c in sorted(callees.get(0x12cb74, ()))])
print("=== callees of nSign 0xdb1cc ===")
print([hex(c) for c in sorted(callees.get(0xdb1cc, ()))])
print("=== callees of nOnResume 0xda4b0 ===")
print([hex(c) for c in sorted(callees.get(0xda4b0, ()))])
print("=== callees of VM program 0x100094 ===")
print([hex(c) for c in sorted(callees.get(0x100094, ()))])
print("=== mid-function bl targets from 0x100094 (first 20) ===")
print([hex(x) for x in mid_bl[0x100094][:20]], "total:", len(mid_bl[0x100094]))

# ---- who references the .data pointer tables 0x1549d8..0x154ac0?
print("\n=== functions referencing .data table 0x1549d8-0x154ac0 ===")
for s, f in feat.items():
    for t in f['bl']:
        pass
# re-derive adrp refs from feat: we saved only classified counts... redo quickly with raw scan
# (feat.json saved only counts for drr/data. Instead rescan .text for adrp/add pairs pointing there.)
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN); md.detail=False
hits = defaultdict(list)
for s, z in fdes:
    adrpv = {}
    for ins in md.disasm(d[s:s+z], s):
        if ins.mnemonic == 'adrp':
            reg, page = ins.op_str.split(', ')
            adrpv[reg] = int(page.lstrip('#'), 0)
        elif ins.mnemonic == 'add' and adrpv:
            ps = ins.op_str.replace(' ','').split(',')
            if len(ps) == 3 and ps[1] in adrpv and ps[2].startswith('#'):
                try: full = adrpv[ps[1]] + int(ps[2].lstrip('#'), 0)
                except ValueError: continue
                if 0x1549d8 <= full < 0x154ac8:
                    hits[s].append(hex(full))
for s, hh in sorted(hits.items()):
    print("  %s (%s): %s" % (hex(s), region(s), hh))

# ---- giant R1 functions: mnemonic profile
print("\n=== giant functions profile ===")
for s in (0x6f990, 0x81008, 0x51780, 0x3c178, 0x8d6f4, 0x3348c, 0xeb6f8, 0x2c594, 0x1400cc):
    f = feat[str(s)]
    mn = Counter(dict(f['top_mn']))
    print("  %s (%s) size=%7d n=%6d  bl=%d blr=%d br=%d  top: %s" % (
        hex(s), f['region'], f['size'], f['n'], len(f['bl']), f['blr'], f['br'],
        f['top_mn'][:6]))

# ---- call count per function (in-degree) for R1 giants
print("\nin-degree of giants:", {hex(s): len(callers.get(s, ())) for s in (0x6f990, 0x81008, 0x51780, 0x3c178, 0x8d6f4, 0x3348c, 0xeb6f8, 0x2c594, 0x1400cc)})
