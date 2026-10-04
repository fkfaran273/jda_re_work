"""iOS header: the srand48/lrand48 hypothesis (Apple libc maps rand->lrand48).

lrand48:  X' = (0x5DEECE66D * X + 0xB) mod 2^48,  output = X >> 17  (31-bit)
srand48:  X  = (seed << 16) | 0x330E
NOTE: Java's LCG seeds differently (seed ^ 0x5DEECE66D), so the earlier Java
test did NOT cover this. Also tests: warmup discards, mrand48, ms/us seeds.
"""
import base64, re, sys, zipfile, struct
from datetime import datetime

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run")

SAZ = r"C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
z = zipfile.ZipFile(SAZ)
rows = []
for n in sorted(z.namelist()):
    if n.endswith("_c.txt"):
        d = z.read(n).decode("utf8", errors="replace")
        m = re.search(r'signature="([^"]+)"', d)
        if m:
            rows.append((int(re.search(r"(\d+)_c", n).group(1)),
                         base64.b64decode(m.group(1))[:16]))
times = {}
for n in z.namelist():
    if n.endswith("_m.xml"):
        sid = int(re.search(r"(\d+)_m", n).group(1))
        t = re.search(r'ClientBeginRequest="([^"]+)"', z.read(n).decode("utf8", "replace"))
        if t:
            times[sid] = datetime.fromisoformat(t.group(1).replace("Z", "+00:00")).timestamp()

M = (1 << 48) - 1
A, C = 0x5DEECE66D, 0xB


def lrand48_stream(seed, n=8, warmup=0):
    X = (((seed & 0xFFFFFFFF) << 16) | 0x330E) & M
    out = []
    for _ in range(n + warmup):
        X = (A * X + C) & M
        out.append(X >> 17)
    return out[warmup:]


def mrand48_stream(seed, n=8, warmup=0):
    X = (((seed & 0xFFFFFFFF) << 16) | 0x330E) & M
    out = []
    for _ in range(n + warmup):
        X = (A * X + C) & M
        out.append(X >> 16)
    return out[warmup:]


def pair(d):
    return b"".join(struct.pack(">I", (d[i] ^ d[i + 1]) & 0xFFFFFFFF)
                    for i in range(0, 8, 2))


print("=== 0. sanity: do the 3 shared-header requests really share a second? ===")
from collections import defaultdict
by_hdr = defaultdict(list)
for sid, h in rows:
    if sid in times:
        by_hdr[h.hex()].append((sid, int(times[sid]), round(times[sid] % 60, 3)))
for k, v in by_hdr.items():
    if len(v) > 1:
        print(f"  hdr {k[:16]}... : {v}")
secs = sorted({int(times[s]) for s, _ in rows if s in times})
print(f"  distinct seconds: {len(secs)}  distinct headers: {len(by_hdr)}")
same_sec_diff_hdr = [s for s in secs if len({h.hex() for sid, h in rows
                      if sid in times and int(times[sid]) == s}) > 1]
print(f"  seconds containing >1 DIFFERENT header: {same_sec_diff_hdr or 'none'}")

print("\n=== 1. lrand48 sweep (seed variants x warmup 0..64) ===")
SEEDS = {
    "sec": lambda t: int(t),
    "sec-1": lambda t: int(t) - 1,
    "sec+1": lambda t: int(t) + 1,
    "sec-2": lambda t: int(t) - 2,
    "ms": lambda t: int(t * 1000),
    "ms%2^31": lambda t: int(t * 1000) & 0x7FFFFFFF,
}
best = (0, None)
for sname, sf in SEEDS.items():
    for warm in range(0, 65):
        for gen, gname in ((lrand48_stream, "lrand48"), (mrand48_stream, "mrand48")):
            ok = sum(1 for sid, h in rows if sid in times
                     and pair(gen(sf(times[sid]), 8, warm)) == h)
            if ok > best[0]:
                best = (ok, (gname, sname, warm))
            if ok:
                print(f"  HIT {gname} seed={sname} warmup={warm}: {ok}/{len(rows)}")
print(f"  best: {best[0]}/{len(rows)} {best[1]}")

print("\n=== 2. full 31-bit lrand48 direct-draw layout too ===")
for sname, sf in SEEDS.items():
    for warm in (0, 1, 2):
        ok = sum(1 for sid, h in rows if sid in times
                 and b"".join(struct.pack(">I", x & 0x7FFFFFFF)
                              for x in lrand48_stream(sf(times[sid]), 4, warm)) == h)
        if ok:
            print(f"  HIT direct-draw seed={sname} warmup={warm}: {ok}/{len(rows)}")
print("  (done)")