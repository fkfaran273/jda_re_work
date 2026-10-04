"""t9 -- init_array funcs, 0x95fc4/0xe2be0/0xda97c/0x12cb74/0xbb548 disasm, DRR table analysis."""
import struct, json, io, sys
import capstone
from collections import defaultdict, Counter

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fsize = {f[0]: f[1] for f in fdes}
feat = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/feat.json"))
edges = [(a, b) for a, b in json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/edges.json"))["edges"]]

def region(a):
    if a < 0x99000: return 'R1'
    if a < 0xBCA30: return 'M1'
    if a < 0x100094: return 'R2'
    if a < 0x12AA48: return 'M2'
    if a < 0x146000: return 'R3'
    return 'M3'

gotplt_by_addr = {int(k, 16): v for k, v in json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/gotplt.json"))["gotplt"].items()}
plt_start, plt_end = 0x1489c0, 0x1489c0 + 0x4a0
plt_map = {}
md0 = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
ad = plt_start; adrpv0 = {}
while ad < plt_end:
    for ins in md0.disasm(d[ad:ad+16], ad):
        if ins.mnemonic == 'adrp':
            r, pg = ins.op_str.split(', ')
            adrpv0[r] = int(pg.lstrip('#'), 0)
        elif ins.mnemonic == 'ldr' and adrpv0:
            ops = ins.op_str; b = ops.find('[')
            if b != -1:
                inner = ops[b+1:ops.find(']')].split(',')
                base = inner[0].strip()
                off = int(inner[1].strip().lstrip('#'), 0) if len(inner) > 1 else 0
                if base in adrpv0: plt_map[ad] = adrpv0[base] + off
    ad += 16
name_of_plt = {s: n for s, n in ((s, gotplt_by_addr.get(g)) for s, g in plt_map.items()) if n}

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
def dis(s, out, maxn=None):
    z = fsize[s]
    print("\n=== %s (region %s, %d bytes) ===" % (hex(s), region(s), z), file=out)
    adrpv = {}
    n = 0
    for ins in md.disasm(d[s:s+z], s):
        m, ops = ins.mnemonic, ins.op_str
        note = ""
        if m == 'adrp':
            r, pg = ops.split(', ')
            adrpv[r] = int(pg.lstrip('#'), 0)
        elif m == 'bl':
            t = int(ops.lstrip('#'), 0)
            note = "  ; PLT->" + name_of_plt[t] if (plt_start <= t < plt_end and name_of_plt.get(t)) else "  ; -> " + hex(t)
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
            print("  ... truncated", file=out); break

buf = io.StringIO()
for s in (0x148414, 0x1488e4, 0x13d874, 0x12cb74):
    dis(s, buf)
open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/init_dis.txt", "w").write(buf.getvalue())
print("init_dis.txt written", len(buf.getvalue()))

# ---- DRR table: full dump of entries and which functions they point to
fset = set(fsize)
rela_off, rela_size = 0x10f8, 0x1da0
drr_entries = []
for i in range(rela_size // 24):
    o = rela_off + i * 24
    r_off, r_info, r_add = struct.unpack_from('<QQq', d, o)
    if 0x14ce60 <= r_off < 0x14d7c0 and (r_info & 0xffffffff) == 0x403:
        drr_entries.append((r_off, r_add))
drr_entries.sort()
byreg = Counter(region(a) for _, a in drr_entries if a in fset)
print("\nDRR table: %d entries, target regions: %s" % (len(drr_entries), dict(sorted(byreg.items()))))
print("first 12 entries:", [(hex(o), hex(a)) for o, a in drr_entries[:12]])
print("last 12 entries:", [(hex(o), hex(a)) for o, a in drr_entries[-12:]])
# are targets in one contiguous VA cluster?
tg = sorted(a for _, a in drr_entries)
print("target VA range: %s .. %s" % (hex(tg[0]), hex(tg[-1])))
# gaps in target list
gaps = [(tg[i], tg[i+1]-tg[i]) for i in range(len(tg)-1) if tg[i+1]-tg[i] > 0x400]
print("target gaps > 0x400:", [(hex(a), g) for a, g in gaps][:10])

# callers of the 4 DRR-referencing functions
callers = defaultdict(set); callees = defaultdict(set)
for a, b in edges:
    if b in fset and a in fset:
        callees[a].add(b); callers[b].add(a)
print("\ncallers of 0x8be0:", [hex(x) for x in callers.get(0x8be0, ())])
print("callers of 0x8c14:", [hex(x) for x in callers.get(0x8c14, ())])
print("callers of 0x15384:", [hex(x) for x in callers.get(0x15384, ())])
print("callers of 0x13f434:", [hex(x) for x in callers.get(0x13f434, ())])
print("callees of 0x8be0:", [hex(x) for x in callees.get(0x8be0, ())])
print("callees of 0x8c14:", [hex(x) for x in callees.get(0x8c14, ())])
print("callees of 0x13f434:", [hex(x) for x in callees.get(0x13f434, ())])

# ---- who calls the R2 indirect-call cluster and the giants
for s in (0xd0838, 0xd505c, 0xd417c, 0xcc39c, 0x6f990, 0x81008, 0x51780, 0x3c178, 0x8d6f4, 0x3348c, 0xeb6f8, 0x97414, 0x2c594, 0x1400cc, 0x13ef40, 0x13f7a4):
    print("callers of %s (%s,%d): %s" % (hex(s), region(s), fsize[s], [hex(x) for x in sorted(callers.get(s, ()))][:12]))

# ---- R2/R3 clusters: list all functions with callers/callees summary around the signing path
print("\n=== 0x12cb74 callees detail ===")
for c in sorted(callees.get(0x12cb74, ())):
    print("  %s (%s) size=%d" % (hex(c), region(c), fsize[c]))
print("\n=== 0xda97c callees ===")
for c in sorted(callees.get(0xda97c, ())):
    print("  %s (%s) size=%d" % (hex(c), region(c), fsize[c]))
