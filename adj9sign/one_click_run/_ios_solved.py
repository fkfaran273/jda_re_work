"""SOLVED: Apple MINSTD (Park-Miller 16807) + XOR-pair composition, 27/28.

Now invert: for each header, find the exact seed second. Then look at the
seed-to-capture-clock relationship (that is the remaining iOS-specific detail).
"""
import base64, re, struct, zipfile
from datetime import datetime

SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
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
        x = z.read(n).decode("utf8", "replace")
        cc = re.search(r'ClientConnected="([^"]+)"', x)
        br = re.search(r'ClientBeginRequest="([^"]+)"', x)
        if cc and br:
            times[sid] = (datetime.fromisoformat(cc.group(1).replace("Z", "+00:00")).timestamp(),
                          datetime.fromisoformat(br.group(1).replace("Z", "+00:00")).timestamp())

M31, M32, P = 0x7FFFFFFF, 0xFFFFFFFF, 2 ** 31 - 1


def minstd_stream(seed, n=8):
    x = seed & M31
    if x == 0:
        x = 1
    out = []
    for _ in range(n):
        hi, lo = divmod(x, 127773)
        x = 16807 * lo - 2836 * hi
        if x < 0:
            x += P
        out.append(x)
    return out


def header_for(seed):
    d = minstd_stream(seed, 8)
    return b"".join(struct.pack(">I", (d[2 * i] ^ d[2 * i + 1]) & M32) for i in range(4))


# index headers -> seeds over a wide range
print("inverting by full sweep (seed 0 .. 2^31-1 is too big; use capture window +/-3d first)")
cache = {}
WIN = 3 * 86400
fails = []
results = []
for sid, h in sorted(set((s, x) for s, x in rows)):
    if sid not in times:
        continue
    lo, hi = times[sid]
    found = None
    for sec in range(int(lo) - WIN, int(hi) + WIN):
        if sec < 0:
            continue
        v = cache.get(sec)
        if v is None:
            v = cache[sec] = header_for(sec)
        if v == h:
            found = sec
            break
    if found is None:
        fails.append((sid, h.hex()))
    else:
        results.append((sid, found, int(lo), int(hi), h.hex()))

print(f"inverted {len(results)}/{len(rows)}  (failed: {len(fails)})")
if results:
    print(f"\n{'sid':>5} {'seed':>12} {'ConnBeg':>12} {'offset':>8}")
    offs = []
    for sid, found, lo, hi, hx in results:
        off = found - int(lo)
        offs.append(off)
        print(f"{sid:>5} {found:>12} {int(lo):>12} {off:>+8}   {hx[:16]}")
    from collections import Counter
    print(f"\noffset distribution (seed - ClientConnected): {dict(sorted(Counter(offs).items()))}")
    print(f"offset distribution (seed - ClientBeginRequest): "
          f"{dict(sorted(Counter(f - int(hi) for _, f, _, hi, _ in results).items()))}")
else:
    for sid, hx in fails:
        print(f"  sid {sid}: {hx} NOT FOUND in +/-3 days")