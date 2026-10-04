import os, sys, json, struct, glob, re

scan_dir, maps_file, out_json = sys.argv[1:4]

patA = struct.pack('<4I', 0xbfffffff, 0xfffffd1f, 0x00070000, 0)
patA_be = patA[::-1]                      # full 16B byte-reversed (BE dwords)
patA_dwswap = struct.pack('<4I', 0xfffffd1f, 0xbfffffff, 0, 0x00070000)  # swapped dword order variant
patB = struct.pack('<I', 0xfad0f10d)
patB_be = patB[::-1]
pats = {'A': [patA, patA_be, patA_dwswap], 'B': [patB, patB_be]}

kmap = {}
for line in open(maps_file, errors='replace'):
    m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)', line.strip())
    if not m:
        continue
    lo, hi, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4).strip()
    kmap[lo // 4096] = (lo, hi, name)

hits = []
scanned = 0
for fp in sorted(glob.glob(os.path.join(scan_dir, 'r*.bin'))):
    K = int(os.path.basename(fp)[1:-4])
    data = open(fp, 'rb').read()
    scanned += len(data)
    p = kmap.get(K)
    for pname, plist in pats.items():
        for pat in plist:
            off = 0
            while True:
                i = data.find(pat, off)
                if i < 0:
                    break
                addr = p[0] + i if p else None
                hits.append({'pat': pname, 'variant': plist.index(pat), 'file': os.path.basename(fp), 'off': i,
                             'addr': hex(addr) if addr else None})
                off = i + 1

print(f"scanned {scanned/1e6:.1f} MB, A hits: {sum(1 for h in hits if h['pat']=='A')}, B hits: {sum(1 for h in hits if h['pat']=='B')}")
for h in hits:
    print(h)
# pairing on raw offsets
pairs = []
for a in hits:
    if a['pat'] != 'A' or a['variant'] != 0:
        continue
    for b in hits:
        if b['pat'] == 'B' and b['variant'] == 0 and b['file'] == a['file'] and b['off'] - a['off'] == 0x10:
            pairs.append((a['file'], a['off'], a['addr'], b['addr']))
print(f"pairs (LE, 0x10 apart): {len(pairs)}")
for p in pairs:
    print("PAIR", p)
json.dump(hits, open(out_json, 'w'), indent=1)
