import re, sys, json, os

maps_file = sys.argv[1]
out_json = sys.argv[2]
out_sh = sys.argv[3]
pid = sys.argv[4]

ranges = []
with open(maps_file, 'r', errors='replace') as f:
    for line in f:
        m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)', line.strip())
        if not m:
            continue
        lo, hi, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4).strip()
        if 'r' not in perms or 'w' not in perms:
            continue
        if 'anon:scudo' in name or 'libc_malloc' in name:
            size = hi - lo
            if size > 256 * 1024 * 1024:
                print(f"SKIP >256MB: {lo:x}-{hi:x} {name}")
                continue
            ranges.append({'lo': lo, 'hi': hi, 'name': name})

total = sum(r['hi'] - r['lo'] for r in ranges)
print(f"{len(ranges)} ranges, total {total/1e6:.1f} MB")

plan = []
for r in ranges:
    K = r['lo'] // 4096
    N = r['hi'] - r['lo']
    # pad up to full 4096 blocks; dd count is in blocks
    nblocks = N // 4096
    if N % 4096:
        nblocks += 1
    plan.append({'K': K, 'lo': r['lo'], 'hi': r['hi'], 'size': N, 'nblocks': nblocks, 'name': r['name']})

with open(out_json, 'w') as f:
    json.dump(plan, f, indent=1)

with open(out_sh, 'w') as f:
    f.write("mkdir -p /data/local/tmp/sd1\n")
    for p in plan:
        f.write(f"/debug_ramdisk/su -c 'dd if=/proc/{pid}/mem bs=4096 skip={p['K']} count={p['nblocks']} of=/data/local/tmp/sd1/r{p['K']}.bin' 2>/dev/null\n")
print("plan written")
