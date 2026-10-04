"""t4_fullpass.py -- full capstone pass over .text; per-function features."""
import struct, json, bisect, time
from collections import defaultdict, Counter

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()
TEXT_OFF, TEXT_SIZE = 0x8be0, 0x13fdd4
PLT = (0x1489c0, 0x1489c0 + 0x4a0)

gotplt = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/gotplt.json"))["gotplt"]
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fstarts = [f[0] for f in fdes]
fend = {f[0]: f[0] + f[1] for f in fdes}

def region(a):
    if a < 0x99000: return 'R1'
    if a < 0xBCA30: return 'M1'
    if a < 0x100094: return 'R2'
    if a < 0x12AA48: return 'M2'
    if a < 0x146000: return 'R3'
    return 'M3'

t0 = time.time()
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = False

feat = {}
for s, z in fdes:
    feat[s] = dict(size=z, region=region(s), n=0, mn=Counter(), adrp={}, adr=set(),
                   litpool=set(), bl=set(), blr=0, br=0, ret=0, cbz=0,
                   tbl_blr=0, plt=set(), strimm=defaultdict(set), ldroff=defaultdict(set))

cur = None
data_page = {}   # reg -> page addr (per function; reset on overwrite) -- linear within function
for s, z in fdes:
    cur = s
    f = feat[s]
    adrpv = {}
    code = d[s:s+z]
    for ins in md.disasm(code, s):
        f['n'] += 1
        m = ins.mnemonic
        f['mn'][m] += 1
        ops = ins.op_str
        if m == 'adrp':
            reg, page = ops.split(', ')
            page = page.lstrip('#')
            adrpv[reg] = int(page, 0)
        elif m == 'adr':
            reg, tgt = ops.split(', ')
            f['adr'].add(int(tgt.lstrip('#'), 0))
        elif m in ('bl', 'b') or m.startswith('b.') or m.startswith('cb') or m.startswith('tb'):
            if m == 'bl':
                try:
                    t = int(ops.lstrip('#'), 0)
                    f['bl'].add(t)
                except ValueError: pass
            elif m.startswith('cb'):
                f['cbz'] += 1
        elif m == 'blr':
            f['blr'] += 1
            # was the reg loaded from .data.rel.ro recently?
        elif m == 'br':
            f['br'] += 1
        elif m == 'ret' or m.startswith('ret'):
            f['ret'] += 1
        elif m.startswith('ldr') and '[' not in ops and '#' not in ops:
            # literal pool: ldr x0, 0x1234
            try:
                f['litpool'].add(int(ops.lstrip('#'), 0))
            except ValueError: pass
        elif m.startswith('ldr') or m.startswith('str') or m in ('ldp','stp'):
            # parse "x0, [x19, #8]" style for offset patterns
            ob = ops.find('[')
            if ob != -1:
                inner = ops[ob+1:ops.find(']')]
                parts = [x.strip() for x in inner.split(',')]
                base = parts[0]
                off = 0
                if len(parts) > 1:
                    ps = parts[1]
                    if ps.startswith('#'):
                        try: off = int(ps.lstrip('#'), 0)
                        except ValueError: off = None
                    else:
                        off = 'reg'
                if off is not None and base:
                    if m.startswith('str'):
                        f['strimm'][base].add(off)
                    else:
                        f['ldroff'][base].add(off)
        # track page+off for data refs
        if m == 'add' and adrpv:
            ps = ops.replace(' ', '').split(',')
            if len(ps) == 3 and ps[1] in adrpv and ps[2].startswith('#'):
                try:
                    off = int(ps[2].lstrip('#'), 0)
                except ValueError:
                    continue
                full = adrpv[ps[1]] + off
                f['adrp'].setdefault(full, 0)
                f['adrp'][full] += 1
                f.setdefault('_lastadr', {})
                f['_lastadr'] = None
        # remember ldr from a page reg
        if m.startswith('ldr') and adrpv:
            ob = ops.find('[')
            if ob != -1:
                inner = ops[ob+1:ops.find(']')]
                parts = [x.strip() for x in inner.split(',')]
                if parts[0] in adrpv:
                    off = 0
                    if len(parts) > 1:
                        try: off = int(parts[1].lstrip('#'), 0)
                        except ValueError: pass
                    full = adrpv[parts[0]] + off
                    f['adrp'].setdefault(full, 0)
                    f['adrp'][full] += 1

print("disasm pass done in %.1fs" % (time.time()-t0))

# classify data refs
RODATA = (0x3560, 0x36b0)
DRR    = (0x14ce60, 0x14d7c0)
DATA   = (0x151c20, 0x15522a)
GOTR   = (0x14d9b0, 0x14dc20)

def cls(a):
    if RODATA[0] <= a < RODATA[1]: return 'rodata'
    if DRR[0] <= a < DRR[1]: return 'data.rel.ro'
    if DATA[0] <= a < DATA[1]: return 'data'
    if GOTR[0] <= a < GOTR[1]: return 'got'
    return None

# dump per-function summary
out = {}
for s, f in feat.items():
    refs = defaultdict(int)
    for a, n in f['adrp'].items():
        c = cls(a)
        if c: refs[c] += n
    for a in f['adr']:
        c = cls(a)
        if c: refs[c] += 1
    for a in f['litpool']:
        # literal pool values point anywhere; count .text targets
        pass
    pltc = sorted(set(gotplt.get(hex(p), '?') for p in f['plt'])) if f['plt'] else []
    out[s] = dict(size=f['size'], region=f['region'], n=f['n'],
                  bl=[hex(x) for x in sorted(f['bl'])],
                  blr=f['blr'], br=f['br'],
                  rodata=refs['rodata'], drr=refs['data.rel.ro'],
                  data=refs['data'], got=refs['got'],
                  str_bases={k: len(v) for k, v in f['strimm'].items() if len(v) >= 4},
                  top_mn=f['mn'].most_common(8))
json.dump(out, open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/feat.json", "w"))

# ==== ANALYSIS ====
# 1. who references .rodata?
print("\n=== functions referencing .rodata ===")
for s, f in sorted(feat.items()):
    n = sum(1 for a in list(f['adrp']) + list(f['adr']) if cls(a) == 'rodata')
    if n:
        print("  %s (%s) size=%d rodata_refs=%d -> %s" % (hex(s), f['region'], f['size'], n,
              sorted(hex(a) for a in list(f['adrp']) + list(f['adr']) if cls(a) == 'rodata')))

# 2. who calls into .data.rel.ro-table-based blr? count blr + drr refs
print("\n=== top functions by blr count (indirect calls) ===")
for s, f in sorted(feat.items(), key=lambda kv: -kv[1]['blr'])[:20]:
    refs = sum(1 for a in list(f['adrp']) + list(f['adr']) if cls(a) == 'data.rel.ro')
    print("  %s (%s) size=%d blr=%d drr_refs=%d" % (hex(s), f['region'], f['size'], f['blr'], refs))

# 3. call graph: who calls the big mapped program 0x100094? who calls nSign?
def callers(target):
    r = []
    for s, f in feat.items():
        if target in f['bl']: r.append(s)
    return r
for tgt in (0x100094, 0xdb1cc, 0xda4b0):
    print("\ncallers of %s (%s):" % (hex(tgt), region(tgt)),
          [hex(x) for x in callers(tgt)])

# 4. biggest bl fanout (hubs)
print("\n=== top call fanout ===")
for s, f in sorted(feat.items(), key=lambda kv: -len(kv[1]['bl']))[:15]:
    print("  %s (%s) size=%d nbl=%d" % (hex(s), f['region'], f['size'], len(f['bl'])))

# 5. record assembly candidates: strimm with >=8 distinct small offsets on one base
print("\n=== record-assembly candidates (store-heavy small offsets) ===")
cnt = 0
for s, f in sorted(feat.items()):
    for base, offs in f['strimm'].items():
        ints = [o for o in offs if isinstance(o, int)]
        if len(ints) >= 8 and max(ints) - min(ints) <= 256:
            cnt += 1
            if cnt <= 25:
                print("  %s (%s) size=%d base=%s n_off=%d range=[%d..%d]" % (
                    hex(s), f['region'], f['size'], base, len(ints), min(ints), max(ints)))
print("  total:", cnt)
