"""ALL_LAWS.py - exhaustive relation search across all genuine captures.

Extracts EVERY relation that holds across all rows among:
  #0 words (W0, T0..T3, T0v), #4 words (a0..a7), #2, and their bits.
Then verifies our synth against each found law.

This finds any law we are still violating.
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

FILES = ("all_signings.json", "app_signings.json", "app_signings2.json",
         "app_signings3.json", "app_signings4.json", "app_signings5.json")


def load():
    rows = []
    for f in FILES:
        p = os.path.join(HERE, f)
        if not os.path.exists(p):
            continue
        a = json.load(open(p, encoding="utf-8"))
        for r in (a if isinstance(a, list) else [a]):
            rows.append(r)
    return rows


def w32(hx):
    return [struct.unpack(">I", bytes.fromhex(hx[i:i+8]))[0]
            for i in range(0, len(hx), 8)]


rows = load()
recs = []
for r in rows:
    d0 = w32(r["d0"])
    d4 = w32(r["d4"])
    d2 = int(r["d2"], 16)
    # normalise: find the tile start
    recs.append({"d0": d0, "d4": d4, "d2": d2, "src": r.get("src", "?")})

print("rows: %d" % len(recs))
print()

# ---- name the #0 words ------------------------------------------------
for i, r in enumerate(recs):
    d0 = r["d0"]
    # tile = the 4-word unit that repeats
    tile = None
    for s in range(1, 6):
        u = d0[s:s+4]
        reps = 1
        k = s + 4
        while k + 4 <= 36 and d0[k:k+4] == u:
            reps += 1
            k += 4
        if reps >= 6:
            tile = (s, u, reps)
            break
    r["tile_start"] = tile[0] if tile else None
    r["tile"] = tile[1] if tile else None
    r["reps"] = tile[2] if tile else 0

print("tile structure per row:")
for i, r in enumerate(recs):
    print("  [%2d] W0=%08x tile_start=%s tile=%s reps=%d" % (
        i, r["d0"][0], r["tile_start"],
        ["%08x" % x for x in (r["tile"] or [])], r["reps"]))
print()

# ---- LAW SEARCH ------------------------------------------------------
def check_const(fn, label):
    """fn(rec) -> value; law holds if constant across ALL rows."""
    vals = []
    for r in recs:
        try:
            vals.append(fn(r))
        except Exception:
            return None
    if len(set(vals)) == 1:
        return vals[0]
    return None


LAWS = []


def add(fn, label):
    v = check_const(fn, label)
    if v is not None:
        LAWS.append((label, v))


# base words
for i in range(6):
    add(lambda r, i=i: r["d0"][i], "d0[%d]" % i)
for i in range(8):
    add(lambda r, i=i: r["d4"][i], "d4[%d]" % i)
add(lambda r: r["d2"], "d2")

# tile relations (T0=d0[1], T1=d0[2], T2=d0[3], T3=d0[4], T0v=d0[5])
add(lambda r: r["d0"][4] ^ r["d0"][2], "T3^T1")
add(lambda r: (r["d0"][4] ^ r["d0"][2]) >> 16, "(T3^T1)>>16")
add(lambda r: r["d0"][4] ^ r["d0"][2] ^ ((r["d0"][4] ^ r["d0"][2]) & 0xFFFF) * 0x10001, "(T3^T1) - R||R")
add(lambda r: r["d0"][3] ^ r["d0"][1], "T2^T0")
add(lambda r: (r["d0"][3] ^ r["d0"][1]) >> 16, "(T2^T0)>>16")
add(lambda r: (r["d0"][3] ^ r["d0"][1]) & 0xFFFF, "(T2^T0)&0xffff")
add(lambda r: r["d0"][1] ^ r["d0"][2], "T0^T1")
add(lambda r: (r["d0"][1] ^ r["d0"][2]) & 0xFFFF, "Xlo")
add(lambda r: (r["d0"][1] ^ r["d0"][2]) >> 16, "Xhi")
add(lambda r: r["d0"][5] ^ r["d0"][1], "T0v^T0")
add(lambda r: (r["d0"][5] ^ r["d0"][1]) & 0xFFFF, "(T0v^T0)&0xffff")
add(lambda r: r["d0"][5] ^ r["d0"][0], "T0v^W0")
add(lambda r: r["d0"][0] ^ r["d0"][1], "W0^T0")
add(lambda r: r["d0"][0] ^ r["d0"][2], "W0^T1")

# #4 relations
add(lambda r: r["d4"][6] ^ ((r["d0"][4] ^ r["d0"][2]) & 0xFFFFFFFF), "a6 ^ K13")
add(lambda r: r["d4"][6] ^ ((((r["d0"][4] ^ r["d0"][2]) >> 16) << 16) |
                            ((r["d0"][1] ^ r["d0"][2]) & 0xFFFF)), "a6 ^ bridge")
add(lambda r: r["d4"][6] ^ r["d0"][0], "a6^W0")
add(lambda r: r["d4"][0] ^ r["d4"][1], "a0^a1")
add(lambda r: r["d4"][0] ^ r["d4"][7], "a0^a7")
add(lambda r: r["d4"][1] ^ r["d4"][7], "a1^a7")

# #2 relations
add(lambda r: r["d2"] ^ r["d0"][0], "d2^W0")
add(lambda r: r["d2"] ^ r["d4"][6], "d2^a6")
add(lambda r: r["d2"] ^ ((r["d0"][4] ^ r["d0"][2]) & 0xFFFFFFFF), "d2^K13")

# high-16 / low-16 of each
for i in range(6):
    add(lambda r, i=i: r["d0"][i] >> 16, "d0[%d]hi" % i)
    add(lambda r, i=i: r["d0"][i] & 0xFFFF, "d0[%d]lo" % i)
for i in range(8):
    add(lambda r, i=i: r["d4"][i] >> 16, "d4[%d]hi" % i)
    add(lambda r, i=i: r["d4"][i] & 0xFFFF, "d4[%d]lo" % i)

print("=== LAWS THAT HOLD CONSTANT ACROSS ALL %d ROWS ===" % len(recs))
for label, v in LAWS:
    print("  %-24s = %08x" % (label, v))
print("total constant laws: %d" % len(LAWS))

json.dump([{"law": l, "value": "%08x" % v} for l, v in LAWS],
          open(os.path.join(HERE, "all_laws.json"), "w"), indent=1)
print("saved all_laws.json")