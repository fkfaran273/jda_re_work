"""_bdbg14.py — widened assignment solver over the WHOLE section state.

Sources: section [257..658) (claims block 257..496, header 497..512, gap 513,
record 514..657).  Known values per row; solve consistent (m -> s, c) maps.
"""
import json
import os
import hashlib
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)

D9 = bytes.fromhex(json.load(open("all_signings.json"))[0]["d9"])
SHA_EMPTY = hashlib.sha256(b"").digest()


def init_state(wlfile):
    WL = json.load(open(wlfile))
    st = {}
    for si, ev in enumerate(WL):
        if ev[0] == "E" and ev[2] == 0x5450001000:
            p = ev[3] + ev[4] - 620
            if 257 <= p < 658 and p not in st:
                st[p] = ev[5]
    return st


def section_template(row, wlfile):
    """Return (section dict pos->val, known dict pos->bool) for pos 257..658."""
    st = init_state(wlfile)
    r = json.load(open("all_signings.json"))[row]
    d0 = bytes.fromhex(r["d0"])
    d2 = bytes.fromhex(r["d2"])
    sec = {}
    kn = {}
    # claims block [257..496): actual values (same for same claims)
    for p in range(257, 497):
        sec[p] = st.get(p)
        kn[p] = True
    # header [497..513): actual (row-dependent but KNOWN from wire log;
    # decoder can compute via Random3(second))
    for p in range(497, 514):
        sec[p] = st.get(p)
        kn[p] = True
    # record [514..658)
    for p in range(514, 658):
        sec[p] = st.get(p)
        kn[p] = True
    # mask unknown: hash [560..592) = record[46..78), [642..644) = [128..130)
    for p in list(range(514 + 46, 514 + 78)) + [514 + 128, 514 + 129]:
        kn[p] = False
    return sec, kn


rows = [4, 7]
wls = {4: "_bdbg5_wirelog_row4.json", 7: "_bdbg5_wirelog.json"}
secs, kns, bodies = [], [], []
for row in rows:
    sec, kn = section_template(row, wls[row])
    secs.append(sec)
    kns.append(kn)
    cap = bytes.fromhex(json.load(open("pair_h3.json"))[row]["blob"])
    bodies.append(cap[16:160])

# verify claims block identical between rows
diff_cb = [p for p in range(257, 497) if secs[0][p] != secs[1][p]]
print("claims-block positions differing rows 4 vs 7:", diff_cb[:10],
      "count", len(diff_cb))

maps = {}
for m in range(144):
    cands = []
    for s in range(257, 658):
        if not all(kns[r][s] and secs[r][s] is not None for r in range(len(rows))):
            continue
        c0 = bodies[0][m] ^ secs[0][s]
        if all(bodies[r][m] ^ secs[r][s] == c0 for r in range(1, len(rows))):
            cands.append((s, c0))
    maps[m] = cands

cnt = Counter(len(v) for v in maps.values())
print("candidate-count histogram:", sorted(cnt.items())[:14])
uniq = {m: v[0] for m, v in maps.items() if len(v) == 1}
print("unique maps:", len(uniq))
# which sections do the unique maps draw from?
src_range = Counter()
for m, (s, c) in uniq.items():
    if s < 497:
        src_range["claims"] += 1
    elif s < 514:
        src_range["header"] += 1
    else:
        src_range["record[%d]" % (s - 514)] += 1
print("unique source ranges:", dict(src_range))
print("\nunique (m -> s, c):")
for m in sorted(uniq):
    s, c = uniq[m]
    print("  body[%3d] -> sec[%3d] (rec[%3d])  c=%02x"
          % (m, s, s - 514 if s >= 514 else -1, c))
json.dump({str(m): maps[m] for m in maps}, open("_bdbg14_map.json", "w"))
