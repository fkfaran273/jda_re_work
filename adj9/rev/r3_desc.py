"""r3_desc.py - are #0's 5 informative words PRNG output?

#0 = [W0] + [16-byte tile x8], i.e. only 5 distinct words (slice 123).  The blob
header is Random3(signing_second) (verified law), so the natural next test is
whether W0/tile are *more draws from the same generator* for the signing second,
either raw next() values or the header's xor-pair form.

The signing second is not stored, so each sample is tested over
created_at +- 5 s (the header law makes the true value the one that hits).
"""
import calendar
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import Random3

S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}")


def wall_second(ca):
    dt = datetime.datetime.strptime(ca[:19], "%Y-%m-%dT%H:%M:%S")
    off = ca[-5:]
    sgn = 1 if off[0] == "+" else -1
    return calendar.timegm(dt.timetuple()) - sgn * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)


def words(x, n=4):
    raw = bytes.fromhex(x)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, min(4 * n, len(raw)), 4)]


def gen_streams(seed, n=6000):
    R = Random3(seed)
    raw = [R.next() for _ in range(2 * n)]
    pairs = [raw[2 * i] ^ raw[2 * i + 1] for i in range(n)]
    return raw, pairs


print("%-3s %-22s %-8s %-9s %s" % ("i", "created_at", "ws", "W0", "tile"))
for i, x in enumerate(S):
    m = ISO.search(bytes.fromhex(x["d10"]).decode("latin1"))
    ws = wall_second(m.group(0)) if m else None
    w = words(x["d0"], 5)
    print("%-3d %-22s %-8s %08x  %s" %
          (i, m.group(0)[:19] if m else "-", ws, w[0],
           ["%08x" % v for v in w[1:5]]))

print()
print("--- PRNG search over ws +- 5 s (raw next() and xor-pair streams) ---")
total_hits = 0
for i, x in enumerate(S):
    m = ISO.search(bytes.fromhex(x["d10"]).decode("latin1"))
    if not m:
        continue
    ws = wall_second(m.group(0))
    w = words(x["d0"], 5)
    found = []
    for cand in range(ws - 5, ws + 6):
        raw, pairs = gen_streams(cand, 6000)
        for nm, seq in (("raw", raw), ("pair", pairs)):
            hit = [k for k, v in enumerate(w) if v in seq]
            if hit:
                idxs = [seq.index(w[k]) for k in hit]
                found.append((cand, nm, len(hit), hit[:6], idxs[:6]))
    print("[%2d] ws=%d  matches: %s" % (i, ws, found if found else "none"))
    total_hits += sum(f[2] for f in found)
print("total word hits:", total_hits)