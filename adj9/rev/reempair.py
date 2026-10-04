"""reempair.py - repair pair_h3 rows 2/3 (crowded same-second group).

The bug: rows 2 and 4 both claimed blob 211c2cd4; verifypairs proved row 4
owns it (BYTE-EXACT), so rows 2/3 hold wrong blobs. Their true blobs must be
elsewhere in the capture logs (their own capture is whcap_hits3).

Method:
 1. Harvest every 192-byte nsign blob from ALL adj9_wh*.log logs (hex form).
 2. For each row 2/3, compute the row's body via FinEx (descriptors from
    all_signings) and find every candidate blob whose 44-word body matches.
 3. For a match, the blob's own header inverts to the true second.
"""
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from fin_vm2 import FinEx
from header_gen import make_header

ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
CONST8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
CONST9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
P3 = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
BYD2 = {r["d2"]: r for r in A}
BROKEN = [r for r in P3 if r["i"] in (2, 3)]


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


def row_descs(row):
    z36 = list(struct.unpack(">36I", bytes.fromhex(row["d0"])))
    d9b = bytes.fromhex(row.get("d9", CONST9.hex()))
    d8b = bytes.fromhex(row.get("d8", CONST8.hex()))
    z8 = list(struct.unpack(">8I", bytes.fromhex(row["d4"])))
    d2v = int(row["d2"], 16) if isinstance(row["d2"], str) else row["d2"]
    d7v = int(row["d7"], 16)
    raw10 = bytes.fromhex(row["d10"])
    n10 = len(raw10) // 4
    z10 = list(struct.unpack(">%dI" % n10, raw10))
    by = {0: (36, b(z36)), 9: (5, d9b), 8: (4, d8b),
          4: (8, b(z8)), 2: (1, b([d2v])), 7: (1, b([d7v])),
          10: (n10, b(z10)), 5: (1, b"\x00" * 4), 6: (1, b"\x00" * 4),
          1: (0, b""), 3: (0, b"")}
    return [(by[i][0], 0, by[i][1]) for i in ORDER]


def finex_out(descs, sec):
    ex = FinEx(sec, descs)
    st = ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = struct.unpack(">4I", make_header(sec))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    if stream is None:
        return None, st
    return b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48)), st


def invert_second(hdr16):
    # scan a window around the captured nsign second, prefer nearest
    base = r["second"]
    for delta in range(0, 200001):
        for sec in (base + delta, base - delta) if delta else (base,):
            if make_header(sec) == hdr16:
                return sec
    return None


# 1. harvest all 192-byte blobs from the logs (as hex) + nsign ts
HEXRE = re.compile(r"nsign utf8len=\d+ ts=(\d+)\s+text: len=192\s+nano_out=\d+\s+hex=([0-9a-f]{384})")
logdir = os.path.join(HERE, "..", "device")
cands = {}
for log in sorted(os.listdir(logdir)):
    if log.startswith("adj9_wh") and log.endswith(".log"):
        path = os.path.join(logdir, log)
        if os.path.getsize(path) == 0:
            continue
        n = 0
        for m in HEXRE.finditer(open(path, encoding="utf-8", errors="replace").read()):
            cands.setdefault(m.group(2), (log, int(m.group(1))))
            n += 1
        print("%s: %d blob mentions" % (log, n), flush=True)
print("distinct candidate blobs: %d" % len(cands), flush=True)

# bodies of candidates
cand_bodies = {}
for bh, (log, ts) in cands.items():
    raw = bytes.fromhex(bh)
    cand_bodies[raw[16:]] = (bh, log, ts)   # body -> (full blob, log, ts)
print("distinct candidate bodies: %d" % len(cand_bodies), flush=True)

# 2. body-match rows 2/3
fixed = 0
for r in BROKEN:
    i = r["i"]
    row = BYD2.get(r["d2"])
    if row is None:
        print("row %d: no all_signings entry" % i)
        continue
    got, st = finex_out(row_descs(row), r["second"])
    if got is None:
        print("row %d: FinEx produced no blob at sec %d" % (i, r["second"]))
        continue
    body = got[16:]
    hit = cand_bodies.get(body)
    if hit is None:
        print("row %d (d2=%s): NO candidate blob matches the computed body" % (i, r["d2"]))
        continue
    bh, log, ts = hit
    hdr16 = bytes.fromhex(bh)[:16]
    sec = invert_second(hdr16)
    r["blob"] = bh
    r["log"] = log
    r["nsign_ts"] = ts
    if sec:
        r["second"] = sec
    print("row %d (d2=%s): MATCHED blob=%s... log=%s ts=%d sec=%s" %
          (i, r["d2"], bh[:16], log, ts, sec), flush=True)
    fixed += 1

if fixed:
    json.dump(P3, open(os.path.join(HERE, "pair_h3.json"), "w"), indent=1)
    print("saved pair_h3.json with %d repaired rows" % fixed)
else:
    print("nothing repaired")
