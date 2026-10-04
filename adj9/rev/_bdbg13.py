"""_bdbg13.py — assignment solver: map body bytes -> layer bytes.

For rows with the same claims (4, 7) solve consistent (body_pos -> layer_pos)
byte maps:  body_r[m] ^ layer_r[s] must be equal across rows for the true
mapping.  Layer template per row known except the 32-byte hash [46..78).
"""
import json
import os
import struct
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)

D9 = bytes.fromhex(json.load(open("all_signings.json"))[0]["d9"])
SHA_EMPTY = hashlib.sha256(b"").digest()


def init_layer(wlfile):
    WL = json.load(open(wlfile))
    st = {}
    for si, ev in enumerate(WL):
        if ev[0] == "E" and ev[2] == 0x5450001000:
            p = ev[3] + ev[4] - 620
            if 514 <= p < 658 and p not in st:
                st[p] = ev[5]
    return bytes(st[i] for i in range(514, 658))


def layer_template(row, wlfile):
    """Return (layer_bytes, known_mask) — known_mask[s]=1 if value known."""
    r = json.load(open("all_signings.json"))[row]
    d0 = bytes.fromhex(r["d0"])
    d2 = bytes.fromhex(r["d2"])
    lay = bytearray(144)
    known = bytearray(144)
    lay[0:3] = b"\x01\x00\x08"; known[0:3] = b"\x01" * 3
    head = b"".join(bytes([(w >> 16) & 0xFF, (w >> 24) & 0xFF, w & 0xFF, (w >> 8) & 0xFF])
                    for w in (int.from_bytes(d0[i:i + 4], "big") for i in range(0, 16, 4)))
    lay[3:19] = head; known[3:19] = b"\x01" * 16
    lay[19] = 2; known[19] = 1
    lay[20:24] = d2[::-1]; known[20:24] = b"\x01" * 4
    lay[24] = 3; known[24] = 1
    lay[25:45] = D9; known[25:45] = b"\x01" * 20
    lay[45] = 4; known[45] = 1
    # [46..78) hash unknown
    lay[78] = 5; known[78] = 1
    lay[79:111] = SHA_EMPTY; known[79:111] = b"\x01" * 32
    lay[111] = 6; known[111] = 1
    lay[112] = 1; known[112] = 1
    lay[113] = 7; known[113] = 1
    lay[114:128] = b"\x00" * 14; known[114:128] = b"\x01" * 14
    lay[128:144] = b"\x0e" * 16; known[128:144] = b"\x01" * 16
    # sanity vs actual initial layer where available
    actual = init_layer(wlfile)
    mism = [s for s in range(144) if known[s] and actual[s] != lay[s]]
    return bytes(lay), bytes(known), actual, mism


rows = [4, 7]
layers = []
bodies = []
for row, wl in ((4, "_bdbg5_wirelog_row4.json"), (7, "_bdbg5_wirelog.json")):
    lay, known, actual, mism = layer_template(row, wl)
    print("row %d template mismatches vs actual initial layer: %s"
          % (row, mism))
    print("   actual[46:78] (hash):", actual[46:78].hex())
    layers.append(actual)          # use ACTUAL (hash included, but mask it)
    cap = bytes.fromhex(json.load(open("pair_h3.json"))[row]["blob"])
    bodies.append(cap[16:160])

knowns = []
for row, wl in ((4, "_bdbg5_wirelog_row4.json"), (7, "_bdbg5_wirelog.json")):
    _, known, _, _ = layer_template(row, wl)
    knowns.append(bytearray(known))
# hash positions + [128..130) unknown in every row
for s in list(range(46, 78)) + [128, 129]:
    for k in knowns:
        k[s] = 0

# solver
maps = {}
for m in range(144):
    cands = []
    for s in range(144):
        if not all(knowns[r][s] for r in range(len(rows))):
            continue
        c0 = bodies[0][m] ^ layers[0][s]
        if all(bodies[r][m] ^ layers[r][s] == c0 for r in range(1, len(rows))):
            cands.append((s, c0))
    maps[m] = cands

uniq = sum(1 for m in maps if len(maps[m]) == 1)
multi = sum(1 for m in maps if 1 < len(maps[m]) <= 6)
many = sum(1 for m in maps if len(maps[m]) > 6)
none = sum(1 for m in maps if len(maps[m]) == 0)
print("\nunique: %d  few(2-6): %d  many(>6): %d  none: %d"
      % (uniq, multi, many, none))
# distribution of candidate counts
from collections import Counter
print("candidate-count histogram:", sorted(Counter(len(v) for v in maps.values()).items())[:12])
# show the unique map
inv = {}
for m in range(144):
    if len(maps[m]) == 1:
        s, c = maps[m][0]
        inv[s] = (m, c)
print("\nunique source->body assignments (s: m, c):")
for s in sorted(inv):
    print("  %3d -> %3d  c=%02x" % (s, inv[s][0], inv[s][1]))
json.dump({str(m): maps[m] for m in maps},
          open("_bdbg13_map.json", "w"))
