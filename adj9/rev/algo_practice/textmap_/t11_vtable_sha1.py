"""t11 -- vtable-call pattern in M1; SHA-1 cluster extent; giant fn buffer spans."""
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
callers = defaultdict(set); callees = defaultdict(set); midbl = defaultdict(set)
for site, tgt in edges:
    f = func_of(site)
    if f is None: continue
    if tgt in fsize: callees[f].add(tgt); callers[tgt].add(f)
    else: midbl[f].add(tgt)

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

# (a) callers of SHA-1 init 0x12e5f4 + SHA-1-related functions: who calls 0x12e5f4?
print("callers of SHA1-init 0x12e5f4:", [hex(x) for x in callers.get(0x12e5f4, ())])
print("callers of 0x136f9c:", [hex(x) for x in callers.get(0x136f9c, ())])
print("callers of 0x13ade4:", [hex(x) for x in callers.get(0x13ade4, ())])
print("midbl into 0x136f9c/0x13ade4/0x3c178/0xeb6f8:",
      {hex(t): [hex(f) for f in fs] for t, fs in
       [(t, {f for f, ts in midbl.items() if t in ts}) for t in (0x136f9c, 0x13ade4, 0x3c178, 0xeb6f8)]})

# R3 cluster 0x136000-0x141000: list functions with sizes and callers
print("\nR3 cluster listing (0x12a000-0x146000):")
for s, z in fdes:
    if 0x12AA48 <= s < 0x146000:
        print("  %s size=%6d ncallers=%d" % (hex(s), z, len(callers.get(s, ()))))

# (b) does any R3/R1 function loop 80 times (SHA-1 rounds)? search for cmp #0x4f / #0x50 / #0x4e in R3 giants
print("\ncmp #0x4f/#0x50 counts (SHA1 round loops):")
for s in (0x136f9c, 0x13ade4, 0x1400cc, 0x13f7a4, 0x13ef40):
    cnt = 0
    for ins in md.disasm(d[s:s+fsize[s]], s):
        if ins.mnemonic == 'cmp' and ins.op_str.split('#')[-1].strip() in ('0x4f','0x50','0x4e','79','80'):
            cnt += 1
    print("  %s: %d" % (hex(s), cnt))

# (c) M1 blr pattern: capture 30 blr sites with preceding 3 instrs
print("\n=== M1 blr context (first 12) ===")
n = 0
for s, z in fdes:
    if region(s) != 'M1': continue
    code = list(md.disasm(d[s:s+z], s))
    for i, ins in enumerate(code):
        if ins.mnemonic == 'blr':
            ctx = code[max(0, i-4):i+1]
            print("  @" + hex(ins.address) + ":")
            for c in ctx:
                print("     %08x: %-8s %s" % (c.address, c.mnemonic, c.op_str))
            n += 1
            if n >= 12: break
    if n >= 12: break

# (d) vtable store: search .text for 'str x8, [x0]' style vptr stores into obj+0
print("\n=== vptr store candidates (str xN, [xM]) in R1/R2 with later DRR-page ldr? skip; instead: ldr xN,[x0]; blr xN with x0=obj ===")
# count per function: 'ldr xK, [xJ]' within 4 instrs before 'blr xK'
pat = defaultdict(int)
for s, z in fdes:
    code = list(md.disasm(d[s:s+z], s))
    for i, ins in enumerate(code):
        if ins.mnemonic == 'blr':
            tgt = ins.op_str
            for j in range(max(0, i-6), i):
                if code[j].mnemonic == 'ldr' and code[j].op_str.split(',')[0] == tgt:
                    off = code[j].op_str.split(',')[-1].strip()
                    if off.startswith('#') or off.startswith('['):
                        pat[(region(s), off)] += 1
                    break
print("  blr-target-loaded-from (region, offset) histogram:", dict(sorted(pat.items(), key=lambda kv: -kv[1])[:20]))

# (e) giant buffer spans: for giants, max contiguous str offset span
print("\n=== giants: store/ldr offset spans and immediate density ===")
for s in (0x6f990, 0x81008, 0x51780, 0x3c178, 0x8d6f4, 0x3348c, 0xeb6f8, 0x2c594, 0xfae0, 0x131dc, 0x14868, 0x10488):
    spans = defaultdict(set)
    nstr = 0; nmovk = 0; nmovz = 0; n = 0
    for ins in md.disasm(d[s:s+fsize[s]], s):
        n += 1
        if ins.mnemonic == 'movk': nmovk += 1
        if ins.mnemonic == 'movz': nmovz += 1
        if ins.mnemonic.startswith('str') or ins.mnemonic.startswith('stur'):
            o = ins.op_str.find('[')
            if o != -1:
                inner = ins.op_str[o+1:ins.op_str.find(']')].split(',')
                if len(inner) >= 2:
                    try: spans[inner[0].strip()].add(int(inner[1].strip().lstrip('#'), 0))
                    except ValueError: pass
    best = []
    for b, offs in spans.items():
        ints = sorted(o for o in offs if isinstance(o, int))
        if ints and len(ints) >= 6:
            best.append((b, len(ints), ints[0], ints[-1]))
    best.sort(key=lambda x: -x[1])
    print("  %s (%s) n=%d movk=%d movz=%d  spans: %s" % (hex(s), region(s), n, nmovk, nmovz,
          [(b, k, lo, hi) for b, k, lo, hi in best[:3]]))
