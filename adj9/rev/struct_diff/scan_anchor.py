import os, sys, json, struct, glob

scan_dir = sys.argv[1]
plan_json = sys.argv[2]
# pattern A: <4I> bfffffff fffffd1f 00070000 00000000
patA = struct.pack('<4I', 0xbfffffff, 0xfffffd1f, 0x00070000, 0)
# pattern B: first dword of #9
patB = struct.pack('<I', 0xfad0f10d)

plan = json.load(open(plan_json))
kmap = {}
for p in plan:
    # K covers pages [K, K+nblocks); a file offset -> addr = lo + off
    kmap[p['K']] = p

hits = []
for fp in sorted(glob.glob(os.path.join(scan_dir, 'r*.bin'))):
    base = os.path.basename(fp)[1:-4]
    K = int(base)
    data = open(fp, 'rb').read()
    # locate actual size from plan
    p = kmap.get(K)
    off = 0
    while True:
        i = data.find(patA, off)
        if i < 0:
            break
        addr = p['lo'] + i if p else None
        hits.append({'pat': 'A', 'file': fp, 'off': i, 'addr': addr, 'K': K})
        off = i + 1
    off = 0
    while True:
        i = data.find(patB, off)
        if i < 0:
            break
        addr = p['lo'] + i if p else None
        hits.append({'pat': 'B', 'file': fp, 'off': i, 'addr': addr, 'K': K})
        off = i + 1

# pair check: A and B hits 0x10 apart (B = A + 0x10, since #9 = #8 + 0x10)
pairs = []
for a in hits:
    if a['pat'] != 'A':
        continue
    for b in hits:
        if b['pat'] == 'B' and b['file'] == a['file'] and b['off'] - a['off'] == 0x10:
            pairs.append((a, b))

print(f"A hits: {sum(1 for h in hits if h['pat']=='A')}, B hits: {sum(1 for h in hits if h['pat']=='B')}, paired(0x10 apart): {len(pairs)}")
for a, b in pairs:
    print(f"PAIR file={os.path.basename(a['file'])} A_off=0x{a['off']:x} A_addr={hex(a['addr']) if a['addr'] else '?'} B_addr={hex(b['addr']) if b['addr'] else '?'}")
json.dump({'hits': hits, 'pairs': [(a['file'], hex(a['off']), hex(a['addr']) if a['addr'] else None, b['off']) for a, b in pairs]}, open(sys.argv[3], 'w'), indent=1)
