"""mine_traces2.py — full whitening I/O extraction from stage-4 traces.

Known: the mint (0001 attribution, sec 1789382946) produced blob 67a33064...
Traces cover heap+stack reads/stores during the whitening phase only.

    python mine_traces2.py
"""
import json
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

BLOB = bytes.fromhex(json.load(open(os.path.join(WORK, "adj7s4_out7.json")))
                     ["out_hex"])
assert len(BLOB) == 304, len(BLOB)
IV = BLOB[:16]
BODY = BLOB[16:272]
print("IV:", IV.hex())
print("body[:32]:", BODY[:32].hex())

reads = []
with open(os.path.join(WORK, "adj7s4_reads.txt")) as f:
    for ln in f:
        p = ln.split()
        if len(p) >= 5:
            reads.append((int(p[1], 16), int(p[2], 16), int(p[3]),
                          int(p[4], 16)))
print("reads:", len(reads))

stores = []
with open(os.path.join(WORK, "adj7s4_stores7.txt")) as f:
    for ln in f:
        p = ln.split()
        if len(p) >= 5:
            stores.append((int(p[1], 16), int(p[2], 16), int(p[3]),
                           int(p[4], 16)))
print("stores:", len(stores))

# ---- 1. where is the final blob written? (direct or word-swapped) ----
def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b) - 3, 4))

targets = {"blob": BLOB, "blob_sw": swap4(BLOB), "body": BODY,
           "body_sw": swap4(BODY)}
st_by_addr = defaultdict(dict)   # addr -> {idx: (size, val)}
for i, (pc, a, s, v) in enumerate(stores):
    st_by_addr[a][i] = (s, v)
addrs = sorted(st_by_addr)
for nm, t in targets.items():
    first = t[:8]
    hits = set()
    for a in addrs:
        # check both the raw first-dword and byte-shifted
        for off in (0,):
            v = st_by_addr[a]
            pass
    # simpler: search the value sequence of consecutive 1/4-byte stores
    valmap = defaultdict(list)
    for i, (pc, a, s, v) in enumerate(stores):
        valmap[v].append((i, a, s))
    needle = int.from_bytes(t[:4], "little")
    for v, lst in valmap.items():
        if v == needle:
            for i, a, s in lst[:4]:
                print(f"{nm}: first-dword store at idx {i} addr {hex(a)} "
                      f"size {s}")
print()
# also: check read VALUES for the swapped blob (if the engine reads back)
rv = defaultdict(list)
for i, (pc, a, s, v) in enumerate(reads):
    rv[v].append((i, a, s))
for nm, t in targets.items():
    needle = int.from_bytes(t[:4], "little")
    if needle in rv:
        print(f"{nm}: first-dword READ at", rv[needle][:4])

# ---- 2. read counters per size: find 16x-read structures ----
for size in (1, 2, 4, 8):
    c = Counter(a for pc, a, s, v in reads if s == size)
    n16 = sorted(a for a, k in c.items() if k == 16)
    runs, cur = [], []
    for a in n16:
        if cur and a == cur[-1] + size:
            cur.append(a)
        else:
            if len(cur) >= 8:
                runs.append((cur[0], len(cur)))
            cur = [a]
    if len(cur) >= 8:
        runs.append((cur[0], len(cur)))
    print(f"size {size}: read-16x addrs {len(n16)}, contiguous runs >=8: "
          f"{[(hex(a), n) for a, n in runs[:8]]}")

# ---- 3. KB362 dwords as READ VALUES (the engine loads key dwords) ----
imm = json.load(open(os.path.join(WORK, "adj7s4_immruns.json")))["d20a0"]
kb_vals = set(w & 0xFFFFFFFF for w in imm)
kb_vals_u = set(w ^ 0xCCCCCCCC for w in imm)
hit_masked = [(hex(a), s) for pc, a, s, v in reads if v in kb_vals]
hit_unmasked = [(hex(a), s) for pc, a, s, v in reads if v in kb_vals_u]
print("reads of KB362 masked dwords:", len(hit_masked),
      hit_masked[:6])
print("reads of KB362 unmasked dwords:", len(hit_unmasked),
      hit_unmasked[:6])

json.dump({"iv": IV.hex(), "blob": BLOB.hex()},
          open(os.path.join(HERE, "mine2_known.json"), "w"))
