"""t14 -- SHA-256 string ref; .data/.bss users; giant store windows; nOnResume chain."""
import struct, json, bisect
import capstone
from collections import defaultdict, Counter

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fstarts = [f[0] for f in fdes]
fsize = {f[0]: f[1] for f in fdes}
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
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

# 1. SHA-256 string (0x3660) usage in 0x97414
print("=== 0x97414: context of the 0x3660 ref ===")
adrpv = {}
code = list(md.disasm(d[0x97414:0x97414+fsize[0x97414]], 0x97414))
for i, ins in enumerate(code):
    if ins.mnemonic == 'adrp':
        r, pg = ins.op_str.split(', '); adrpv[r] = int(pg.lstrip('#'), 0)
    elif ('ldr' in ins.mnemonic or ins.mnemonic == 'add') and adrpv:
        hit = None
        if ins.mnemonic == 'add':
            ps = ins.op_str.replace(' ', '').split(',')
            if len(ps) == 3 and ps[1] in adrpv and ps[2].startswith('#'):
                hit = adrpv[ps[1]] + int(ps[2].lstrip('#'), 0)
        else:
            b = ins.op_str.find('[')
            if b != -1:
                inner = ins.op_str[b+1:ins.op_str.find(']')].split(',')
                if inner[0].strip() in adrpv:
                    off = int(inner[1].strip().lstrip('#'), 0) if len(inner) > 1 else 0
                    hit = adrpv[inner[0].strip()] + off
        if hit == 0x3660:
            for c in code[max(0, i-12):i+24]:
                print("  %08x: %-8s %s" % (c.address, c.mnemonic, c.op_str))
            print("  ----")
            break

# 2. .data users by page
print("\n=== functions referencing .data/.bss pages ===")
users = defaultdict(lambda: defaultdict(int))
for s, z in fdes:
    adrpv = {}
    for ins in md.disasm(d[s:s+z], s):
        if ins.mnemonic == 'adrp':
            r, pg = ins.op_str.split(', ')
            adrpv[r] = int(pg.lstrip('#'), 0)
        elif ins.mnemonic in ('add',) and adrpv:
            ps = ins.op_str.replace(' ', '').split(',')
            if len(ps) == 3 and ps[1] in adrpv and ps[2].startswith('#'):
                try: full = adrpv[ps[1]] + int(ps[2].lstrip('#'), 0)
                except ValueError: continue
                pg = full & ~0xFFF
                if 0x151000 <= pg <= 0x155000:
                    users[pg][s] += 1
for pg in sorted(users):
    fs = users[pg]
    print("  page %s: %d refs in %d funcs; top: %s" % (
        hex(pg), sum(fs.values()), len(fs),
        [(hex(f), n) for f, n in sorted(fs.items(), key=lambda kv: -kv[1])[:8]]))

# who reads the .data pointer table 0x1549d8-0x154ac8?
print("\nrefs to 0x1549d8-0x154ac8 (cfg table):")
for s, z in fdes:
    adrpv = {}
    for ins in md.disasm(d[s:s+z], s):
        if ins.mnemonic == 'adrp':
            r, pg = ins.op_str.split(', '); adrpv[r] = int(pg.lstrip('#'), 0)
        elif adrpv and (ins.mnemonic == 'add' or ins.mnemonic.startswith('ldr')):
            hit = None
            if ins.mnemonic == 'add':
                ps = ins.op_str.replace(' ', '').split(',')
                if len(ps) == 3 and ps[1] in adrpv and ps[2].startswith('#'):
                    hit = adrpv[ps[1]] + int(ps[2].lstrip('#'), 0)
            else:
                b = ins.op_str.find('[')
                if b != -1:
                    inner = ins.op_str[b+1:ins.op_str.find(']')].split(',')
                    if inner[0].strip() in adrpv:
                        off = int(inner[1].strip().lstrip('#'), 0) if len(inner) > 1 else 0
                        hit = adrpv[inner[0].strip()] + off
            if hit is not None and 0x1549d8 <= hit < 0x154ac8:
                print("  %s (%s) @%s -> 0x%x" % (hex(s), region(s), ins.address, hit))

# 3. giant store windows
def window(s, around, n=40):
    z = fsize[s]
    code = list(md.disasm(d[s:s+z], s))
    idx = min(range(len(code)), key=lambda i: abs(code[i].address - around))
    print("\n=== %s window @%s ===" % (hex(s), hex(around)))
    for c in code[max(0, idx-6):idx+n]:
        print("  %08x: %-8s %s" % (c.address, c.mnemonic, c.op_str))

# find a wide store in 0x3348c (base x19)
adrpv = {}
code = list(md.disasm(d[0x3348c:0x3348c+fsize[0x3348c]], 0x3348c))
for i, ins in enumerate(code):
    if ins.mnemonic.startswith('str') and ins.op_str.find('[x19') != -1:
        ps = ins.op_str[ins.op_str.find('[')+1:ins.op_str.find(']')].split(',')
        if len(ps) > 1:
            try:
                off = int(ps[1].strip().lstrip('#'), 0)
                if off > 13000:
                    window(0x3348c, ins.address, 30)
                    break
            except ValueError: pass

# window in 0x2c594 base x0
code = list(md.disasm(d[0x2c594:0x2c594+fsize[0x2c594]], 0x2c594))
for i, ins in enumerate(code):
    if ins.mnemonic.startswith('str') and ins.op_str.find('[x0') != -1:
        ps = ins.op_str[ins.op_str.find('[')+1:ins.op_str.find(']')].split(',')
        if len(ps) > 1:
            try:
                off = int(ps[1].strip().lstrip('#'), 0)
                if off > 6000:
                    window(0x2c594, ins.address, 30)
                    break
            except ValueError: pass

# 4. nOnResume chain: 0xe2be0 -> 0xe3124
print("\n=== 0xe2be0 callees/callers & 0xe3124 ===")
edges = [(a, b) for a, b in json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/edges.json"))["edges"]]
blcallers = defaultdict(set); blcallees = defaultdict(set)
for a, b in edges:
    f = func_of(a)
    if f: blcallees[f].add(b); blcallers[b].add(f)
print("  0xe2be0 callees:", [hex(x) for x in blcallees.get(0xe2be0, ())])
print("  0xe2be0 callers:", [hex(x) for x in blcallers.get(0xe2be0, ())])
print("  0xe3124 callers:", [hex(x) for x in blcallers.get(0xe3124, ())])
print("  0xe3124 callees:", [hex(x) for x in blcallees.get(0xe3124, ())])
