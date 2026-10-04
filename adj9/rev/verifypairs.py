"""verifypairs.py - verify each pair_h3 (row -> second -> blob) by FinEx body.

For each pair_h3 entry: take the all_signings row with matching d2,
run FinEx at the claimed second, compare the 48-word output to the
claimed blob. BYTE-EXACT = pairing confirmed.
"""
import json
import os
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


nok = 0
for r in P3:
    i, sec, bh = r["i"], r["second"], r["blob"]
    row = BYD2.get(r["d2"])
    if row is None:
        print("pair %d d2=%s: NO all_signings row!" % (i, r["d2"]), flush=True)
        nok += 1
        continue
    ex = FinEx(sec, row_descs(row))
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
    got = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48)) if stream is not None else b""
    want = bytes.fromhex(bh)
    diff = (sum(1 for k in range(48) if got[k*4:k*4+4] != want[k*4:k*4+4]) if got else 48)
    ok = got == want
    if not ok:
        nok += 1
    print("pair i=%d d2=%s sec=%d status=%-10s steps=%-9d %s" %
          (i, r["d2"], sec, st, ex.steps, "BYTE-EXACT" if ok else "diff %d/48" % diff),
          flush=True)
print()
print("MISMATCHES: %d / %d" % (nok, len(P3)))
