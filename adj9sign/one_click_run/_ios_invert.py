"""Invert the iOS header to recover the actual MINSTD seeds.

Law:
    seed = time(NULL);  x = seed mod (2^31-1);  if x == 0: x = 1
    d[k] = (16807 * d[k-1]) mod (2^31-1)      # 8 draws, d[0] = x
    w_i  = d[2i] ^ d[2i+1]                     # i = 0..3
    header = BE32(w_0..w_3)

Forward is O(1). Inversion: for every candidate d0 in [1, 2^31-2], walk the
chain and keep the ones whose four words match -> that d0 IS the seed.
Vectorized with numpy; p is just under 2^31 so the full sweep is feasible.
"""
import base64, json, re, struct, sys, zipfile
import numpy as np

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

# distinct headers with the window of plausible seconds
uniq = {}
for sid, h in rows:
    uniq.setdefault(h.hex(), []).append(sid)
print(f"{len(uniq)} distinct headers from {len(rows)} requests")

P = 2147483647          # 2^31 - 1
A = 16807


def forward(seed):
    x = seed % P
    if x == 0:
        x = 1
    d = []
    for _ in range(8):
        x = (A * x) % P
        d.append(x)
    return b"".join(struct.pack(">I", (d[2 * i] ^ d[2 * i + 1]) & 0xFFFFFFFF)
                    for i in range(4))


# capture seconds per request (from the XML timers)
from datetime import datetime
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

print("\n=== forward check: does seed == capture second reproduce the header? ===")
hits = 0
for hx, sids in uniq.items():
    tgt = bytes.fromhex(hx)
    for sid in sids:
        if sid not in times:
            continue
        lo, hi = times[sid]
        if any(forward(int(s)) == tgt for s in range(int(lo), int(hi) + 1)):
            hits += 1
            break
print(f"  matched at capture second: {hits}/{len(uniq)}")

# ---- inversion ------------------------------------------------------
print("\n=== full 2^31 inversion (recovering the real seed per header) ===")
CHUNK = 1 << 23          # 8.4M candidates per vectorized block
base = np.arange(1, P - 1, dtype=np.uint64)
recovered = {}
for hx, sids in uniq.items():
    w = struct.unpack(">4I", bytes.fromhex(hx))
    found = []
    for start in range(0, base.size, CHUNK):
        d0 = base[start:start + CHUNK]
        d1 = (A * d0) % P
        if not np.any((d0 ^ d1) == np.uint64(w[0])):
            continue
        d2 = (A * d1) % P
        d3 = (A * d2) % P
        sel = ((d0 ^ d1) == np.uint64(w[0])) & ((d2 ^ d3) == np.uint64(w[1]))
        if not np.any(sel):
            continue
        d4 = (A * d3) % P
        d5 = (A * d4) % P
        d6 = (A * d5) % P
        d7 = (A * d6) % P
        ok = (sel & ((d4 ^ d5) == np.uint64(w[2])) & ((d6 ^ d7) == np.uint64(w[3])))
        for v in d0[ok]:
            found.append(int(v))
    recovered[hx] = found
    sids_s = ",".join(map(str, sids))
    print(f"  {hx[:24]}... sids={sids_s:<14} seeds={found[:4]}")

print("\n=== compare recovered seeds to capture time ===")
for hx, sids in uniq.items():
    seeds = recovered.get(hx) or []
    if not seeds or sids[0] not in times:
        continue
    lo, hi = times[sids[0]]
    for s in seeds[:3]:
        print(f"  seed {s:<12} | req {lo:.2f}..{hi:.2f} | delta {s - int(hi):>+8}")

json.dump({k: v for k, v in recovered.items()},
          open("_ios_recovered_seeds.json", "w"), indent=1)
print("\nwrote _ios_recovered_seeds.json")