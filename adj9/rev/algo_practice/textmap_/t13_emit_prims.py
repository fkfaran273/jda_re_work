"""t13 -- what do giants emit; primitive callers; SHA-256 string usage."""
import struct, json, re
import capstone
from collections import defaultdict, Counter

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fsize = {f[0]: f[1] for f in fdes}
feat = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/feat.json"))
def region(a):
    if a < 0x99000: return 'R1'
    if a < 0xBCA30: return 'M1'
    if a < 0x100094: return 'R2'
    if a < 0x12AA48: return 'M2'
    if a < 0x146000: return 'R3'
    return 'M3'
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
edges = [(a, b) for a, b in json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/edges.json"))["edges"]]
blcallers = defaultdict(set)
for a, b in edges: blcallers[b].add(a)

PRIMS = [0x146470, 0x146474, 0x146478, 0x146558, 0x146650, 0x146ed8, 0x147120,
         0x147220, 0x1472e8, 0x147304, 0x147630, 0x147734, 0x14784c, 0x147a18, 0x147a20]
print("=== callers of each VM primitive (0x146xxx-0x147a20) ===")
for p in PRIMS:
    print("  %s <- %s" % (hex(p), [hex(x) for x in sorted(blcallers.get(p, ()))][:12]))

# also: any bl to mid-VM (0x100094-0x12AA48) from outside M2?
outs = defaultdict(set)
for a, b in edges:
    fa = a  # site; attribute by region only
    if 0x100094 <= b < 0x12AA48 and not (0x100094 <= a < 0x12AA48):
        outs[b].add(a)
print("\nbl from OUTSIDE M2 into M2 range:", sum(len(v) for v in outs.values()))
for b, sites in sorted(outs.items())[:12]:
    print("  -> %s from %s" % (hex(b), [hex(x) for x in sorted(sites)][:6]))

# ---- 0x97414: what does it do with "SHA-256" (0x3660)?
print("\n=== 0x97414 excerpt around rodata ref ===")
adrpv = {}
code = list(md.disasm(d[0x97414:0x97414+fsize[0x97414]], 0x97414))
for i, ins in enumerate(code):
    if ins.mnemonic == 'adrp':
        r, pg = ins.op_str.split(', '); adrpv[r] = int(pg.lstrip('#'), 0)
    if ins.mnemonic.startswith('ldr') or ins.mnemonic.startswith('add'):
        bkt = ins.op_str.find('[')
        ops2 = ins.op_str.replace(' ', '').split(',')
        if ins.mnemonic == 'add' and len(ops2) == 3 and ops2[1] in adrpv:
            full = adrpv[ops2[1]] + int(ops2[2].lstrip('#'), 0)
            if full == 0x3660:
                for c in code[max(0, i-8):i+20]:
                    print("  %08x: %-8s %s" % (c.address, c.mnemonic, c.op_str))
                break

# ---- constant-emission recovery for giants ------------------------------
def recover(s, maxmem=200000):
    """Linear walk; track reg constants (movz/movk/add/sub imm, mov reg); on str record value."""
    mem = defaultdict(dict)   # base -> off -> value
    regs = {}
    inv = defaultdict(list)   # value -> [(base, off)]
    for ins in md.disasm(d[s:s+fsize[s]], s):
        m, ops = ins.mnemonic, ins.op_str.replace(' ', '')
        try:
            if m == 'movz':
                rd, rest = ops.split(',', 1)
                mm = re.match(r'#(0x[0-9a-f]+|\d+)(,lsl#(\d+))?', rest)
                if mm:
                    v = int(mm.group(1), 0) << (int(mm.group(3) or 0))
                    regs[rd] = v
            elif m == 'movk':
                rd, rest = ops.split(',', 1)
                mm = re.match(r'#(0x[0-9a-f]+|\d+)(,lsl#(\d+))?', rest)
                if mm and rd in regs:
                    sh = int(mm.group(3) or 0)
                    v = int(mm.group(1), 0) << sh
                    regs[rd] = (regs[rd] & ~(0xFFFF << sh)) | v
            elif m == 'mov':
                ps = ops.split(',')
                if len(ps) == 2 and ps[1] in regs and not ps[0].startswith('v') and not ps[1].startswith('v'):
                    regs[ps[0]] = regs[ps[1]]
                elif len(ps) == 2 and re.match(r'^(w|x)zr$', ps[1]):
                    regs[ps[0]] = 0
            elif m in ('add', 'sub'):
                ps = ops.split(',')
                if len(ps) == 3 and ps[1] in regs and ps[2].startswith('#'):
                    imm = int(ps[2].lstrip('#'), 0)
                    if m == 'add': regs[ps[0]] = (regs[ps[1]] + imm) & 0xFFFFFFFFFFFFFFFF
                    else: regs[ps[0]] = (regs[ps[1]] - imm) & 0xFFFFFFFFFFFFFFFF
            elif m in ('str', 'stur', 'strb', 'strh') or m in ('stp',):
                bkt = ops.find('[')
                if bkt == -1: continue
                inner = ops[bkt+1:ops.find(']')].split(',')
                base = inner[0]
                off = 0
                if len(inner) > 1:
                    t = inner[1].strip().lstrip('#')
                    try: off = int(t, 0)
                    except ValueError: continue
                if m in ('stp',):
                    continue
                src = ops[:ops.find(',')].strip()
                if src in regs:
                    v = regs[src]
                    sz = {'strb': 1, 'strh': 2}.get(m, 8 if src.startswith('x') else 4)
                    mem[base][off] = (v, sz)
        except Exception:
            pass
    return mem

import binascii
for s in (0x2c594, 0x3348c, 0x81008, 0x6f990, 0x51780, 0xeb6f8, 0x136f9c, 0x1400cc):
    mem = recover(s)
    print("\n=== %s (%s) emission bases: %s ===" % (hex(s), region(s), {b: len(o) for b, o in mem.items()}))
    for base, offs in mem.items():
        if len(offs) < 8: continue
        lo, hi = min(offs), max(offs)
        buf = bytearray(hi - lo + 8)
        known = 0
        for off, (v, sz) in offs.items():
            if off - lo + sz <= len(buf):
                buf[off - lo: off - lo + sz] = v.to_bytes(sz, 'little')[:len(buf)- (off-lo)] if sz <= len(buf)-(off-lo) else v.to_bytes(sz, 'little')[:max(0, len(buf)-(off-lo))]
                known += 1
        # find printable runs
        runs = []
        i = 0
        while i < len(buf):
            if 32 <= buf[i] < 127:
                j = i
                while j < len(buf) and 32 <= buf[j] < 127: j += 1
                if j - i >= 6: runs.append((i + lo, buf[i:j].decode()))
                i = j
            else: i += 1
        print("  base=%s offs=%d span=[%d..%d] printable-runs=%d" % (base, len(offs), lo, hi, len(runs)))
        for o, t in runs[:14]:
            print("     +%d: %r" % (o, t[:60]))
