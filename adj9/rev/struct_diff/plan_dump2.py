import re, sys, json

maps_file, out_json, out_sh, pid = sys.argv[1:5]

ranges = []
for line in open(maps_file, errors='replace'):
    m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)', line.strip())
    if not m:
        continue
    lo, hi, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4).strip()
    if 'r' not in perms or 'w' not in perms:
        continue
    if '/' in name:
        continue  # file-backed
    size = hi - lo
    if size > 256 * 1024 * 1024:
        print(f"SKIP >256MB: {lo:x}-{hi:x} {name}")
        continue
    ranges.append({'lo': lo, 'hi': hi, 'name': name})

total = sum(r['hi'] - r['lo'] for r in ranges)
print(f"{len(ranges)} anon rw ranges, total {total/1e6:.1f} MB")

plan = []
for r in ranges:
    K = r['lo'] // 4096
    nblocks = (r['hi'] - r['lo'] + 4095) // 4096
    plan.append({'K': K, 'lo': r['lo'], 'hi': r['hi'], 'size': r['hi'] - r['lo'], 'nblocks': nblocks, 'name': r['name']})

json.dump(plan, open(out_json, 'w'), indent=1)
with open(out_sh, 'w') as f:
    f.write("mkdir -p /data/local/tmp/sd2\n")
    for p in plan:
        f.write(f"/debug_ramdisk/su -c 'dd if=/proc/{pid}/mem bs=4096 skip={p['K']} count={p['nblocks']} of=/data/local/tmp/sd2/r{p['K']}.bin' 2>/dev/null\n")
print("plan written")
