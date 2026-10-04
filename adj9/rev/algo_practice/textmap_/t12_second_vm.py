"""t12 -- second-interpreter shape test; record-assembly scan; giant taxonomy."""
import struct, json, bisect
import capstone
from collections import defaultdict, Counter

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fsize = {f[0]: f[1] for f in fdes}
def region(a):
    if a < 0x99000: return 'R1'
    if a < 0xBCA30: return 'M1'
    if a < 0x100094: return 'R2'
    if a < 0x12AA48: return 'M2'
    if a < 0x146000: return 'R3'
    return 'M3'
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

# M2 profile: ldr 31%, mov 28%, bl 17%, cbnz 15%
print("=== functions with M2-like shape (cbnz>=8% and bl>=8%, n>=1000) outside M2 ===")
found = []
for s, z in fdes:
    if region(s) == 'M2': continue
    c = Counter()
    for ins in md.disasm(d[s:s+z], s):
        c[ins.mnemonic] += 1
    n = sum(c.values())
    if n < 1000: continue
    cb = (c['cbnz'] + c['cbz']) / n
    bl = c['bl'] / n
    ld = c['ldr'] / n
    if cb >= 0.08 and bl >= 0.08:
        found.append((s, n, cb, bl, ld))
for s, n, cb, bl, ld in found:
    print("  %s (%s) n=%d cbnz/cbz=%.1f%% bl=%.1f%% ldr=%.1f%%" % (hex(s), region(s), n, 100*cb, 100*bl, 100*ld))
print("  count:", len(found))

print("\n=== functions with cbnz>=10%% anywhere (n>=500) ===")
for s, z in fdes:
    c = Counter()
    for ins in md.disasm(d[s:s+z], s):
        c[ins.mnemonic] += 1
    n = sum(c.values())
    if n < 500: continue
    if (c['cbnz']) / n >= 0.10:
        print("  %s (%s) n=%d cbnz=%.1f%%" % (hex(s), region(s), n, 100*c['cbnz']/n))

# record-assembly: single base with strb/strh/str offsets covering span>=96, >=12 stores
print("\n=== record-assembly scan: dense byte-wise stores on one base, span>=96 ===")
cands = []
for s, z in fdes:
    if region(s) == 'M2': continue
    bases = defaultdict(list)   # base -> (off) for strb/strh/str
    for ins in md.disasm(d[s:s+z], s):
        m = ins.mnemonic
        if m in ('strb', 'strh', 'str') or m.startswith('stur'):
            o = ins.op_str.find('[')
            if o == -1: continue
            inner = ins.op_str[o+1:ins.op_str.find(']')].split(',')
            base = inner[0].strip()
            off = 0
            if len(inner) > 1:
                t = inner[1].strip().lstrip('#')
                try: off = int(t, 0)
                except ValueError: continue
            bases[base].append((off, m))
    for b, lst in bases.items():
        offs = sorted(set(o for o, m in lst))
        ints = [o for o in offs if o >= 0]
        if len(ints) >= 12 and ints[-1] - ints[0] >= 96:
            sb = sum(1 for o, m in lst if m == 'strb')
            cands.append((s, b, len(ints), ints[0], ints[-1], sb))
cands.sort(key=lambda x: -(x[2]))
for s, b, k, lo, hi, sb in cands[:20]:
    print("  %s (%s) base=%s distinct_offs=%d span=[%d..%d] strb=%d" % (hex(s), region(s), b, k, lo, hi, sb))
print("  total:", len(cands))

# giant taxonomy: per giant, count ror/eor/add-sub/mul (hash mix) vs str (fill) vs ldr-sw (table walk)
print("\n=== giant function taxonomy ===")
giants = [0x6f990, 0x81008, 0x51780, 0x3c178, 0x8d6f4, 0x3348c, 0xeb6f8, 0x2c594,
          0x136f9c, 0x13ade4, 0x1400cc, 0x10488, 0x1400cc]
seen = set()
for s in giants:
    if s in seen: continue
    seen.add(s)
    c = Counter()
    for ins in md.disasm(d[s:s+fsize[s]], s):
        c[ins.mnemonic] += 1
    n = sum(c.values())
    mix = c['eor'] + c['ror'] + c['add'] + c['sub'] + c['mul'] + c['madd'] + c['and'] + c['orr'] + c['lsl'] + c['lsr']
    fill = sum(v for k, v in c.items() if k.startswith('str') or k.startswith('stur'))
    br = c['b'] + sum(v for k, v in c.items() if k.startswith('b.'))
    print("  %s (%s) n=%6d  eor=%4d ror=%4d add=%4d sub=%4d mul/madd=%3d  stores=%5d branches=%5d  movk=%d" % (
        hex(s), region(s), n, c['eor'], c['ror'], c['add'], c['sub'], c['mul']+c['madd'], fill, br, c['movk']))
