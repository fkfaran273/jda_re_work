"""t2_relocs_fdes.py -- where do RELATIVE relocs point; FDE stats per region."""
import struct, json

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()

rela_off, rela_size = 0x10f8, 0x1da0
rel = []
for i in range(rela_size // 24):
    o = rela_off + i * 24
    r_off, r_info, r_add = struct.unpack_from('<QQq', d, o)
    rel.append((r_off, r_info & 0xffffffff, r_info >> 32, r_add))

abs64 = [r for r in rel if r[1] == 0x101]
relrel = [r for r in rel if r[1] == 0x403]
print("ABS64 relocs:")
for r in abs64:
    print("  at %s sym=%d addend=%s" % (hex(r[0]), r[2], hex(r[3])))

print("\nRELATIVE reloc destinations (by target region):")
regions = {}
for r in relrel:
    off = r[0]
    if 0x14ce60 <= off < 0x14d7c0: k = '.data.rel.ro'
    elif 0x151c20 <= off < 0x155230: k = '.data'
    elif 0x14d9b0 <= off < 0x14d9c8: k = '.got'
    elif 0x14d9c8 <= off < 0x14dc20: k = '.got.plt'
    elif 0x14d7c0 <= off < 0x14d7e0: k = 'init/fini_array'
    else: k = 'other'
    regions.setdefault(k, []).append(r)
for k, v in regions.items():
    print("  %s: %d relocs" % (k, len(v)))

fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fset = set(f[0] for f in fdes)
fends = {f[0]: f[0] + f[1] for f in fdes}

# What do .data.rel.ro relocs point to?
drr = [r for r in relrel if 0x14ce60 <= r[0] < 0x14d7c0]
drr.sort()
print("\n.data.rel.ro reloc addends, first 40:")
infunc = 0; notfunc = 0
targets = {}
for r in drr:
    a = r[3]
    targets[a] = targets.get(a, 0) + 1
    if a in fset: infunc += 1
    else: notfunc += 1
print("  distinct addends:", len(targets), " pointing at function starts:", infunc, " not:", notfunc)
for r in drr[:40]:
    mark = "FUNC" if r[3] in fset else "    "
    print("  [%s] %s -> %s" % (mark, hex(r[0]), hex(r[3])))
print("  layout: contiguous ascending offsets?", all(drr[i+1][0] - drr[i][0] == 8 for i in range(len(drr)-1)))
print("  offset range:", hex(drr[0][0]), "-", hex(drr[-1][0]))

# addends that are NOT function starts: what are they?
nf = sorted(set(r[3] for r in drr if r[3] not in fset))
print("  non-function addends (%d):" % len(nf), [hex(x) for x in nf[:40]])

# .data relocs
drel = [r for r in relrel if 0x151c20 <= r[0] < 0x155230]
print("\n.data relocs:", len(drel))
for r in sorted(drel)[:40]:
    mark = "FUNC" if r[3] in fset else "    "
    print("  [%s] %s -> %s" % (mark, hex(r[0]), hex(r[3])))

# ---- FDE stats per region -------------------------------------------------
print("\n=== FUNCTION SIZE STATS PER REGION ===")
def region_of(a):
    if a < 0x99000: return 'R1 unmapped 0x8be0-0x99000'
    if a < 0xBCA30: return 'M1 mapped 0x99000-0xBCA30'
    if a < 0x100094: return 'R2 unmapped 0xBCA30-0x100094'
    if a < 0x12AA48: return 'M2 mapped 0x100094-0x12AA48'
    if a < 0x146000: return 'R3 unmapped 0x12AA48-0x146000'
    return 'M3 mapped 0x146000-0x1489b4'

from collections import defaultdict
stats = defaultdict(lambda: [0, 0, 0, [], 0])  # count, bytes, maxsize, top sizes, instr-est
for a, sz in fdes:
    r = region_of(a)
    s = stats[r]
    s[0] += 1; s[1] += sz; s[2] = max(s[2], sz); s[3].append((sz, a))
    s[4] += sz // 4
for r in sorted(stats):
    s = stats[r]
    s[3].sort(reverse=True)
    print("%-34s funcs=%4d bytes=%9d (~%6d instr) largest:" % (r, s[0], s[1], s[4]),
          [(hex(a), sz) for sz, a in s[3][:6]])

# overall size histogram
import collections
h = collections.Counter()
for a, sz in fdes:
    h[min(sz // 64, 20)] += 1
print("\nsize histogram (x=64B buckets, 20+=1280B+):")
for k in sorted(h):
    print("  %4d-%4d B: %d" % (k*64, k*64+63, h[k]))
