"""audit_pairs.py - is each pair_h3 row's blob actually ITS OWN?

pair_h3.json is a hand-assembled pairing: the blob was matched by header
timestamp, while d0/d2/d4 were copied straight out of all_signings.json
(pair_h3.py:96). reempair.py then patched only rows i in (2,3). Any row whose
blob survived unpatched may belong to a DIFFERENT sample, in which case its
d0/d2/d4 do not describe that blob at all.

This script asks the only question that settles it: feed each row its OWN
descriptors at its OWN second through FinEx and compare the body it produces
against the body stored in the row.

  exact   - row is self-consistent; the blob is genuinely this row's
  body-hits-row-N - the row's blob really belongs to sample N; the row's d0/d2/d4
                     are right but its blob/log/ts were mispaired
  nomatch - neither: the blob is foreign and the recomputed body is unknown
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

P3 = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


def row_descs(row):
    z36 = list(struct.unpack(">36I", bytes.fromhex(row["d0"])))
    z8 = list(struct.unpack(">8I", bytes.fromhex(row["d4"])))
    d2v = int(row["d2"], 16) if isinstance(row["d2"], str) else row["d2"]
    d7v = int(row["d7"], 16)
    raw10 = bytes.fromhex(row["d10"])
    n10 = len(raw10) // 4
    z10 = list(struct.unpack(">%dI" % n10, raw10))
    by = {0: (36, b(z36)), 9: (5, CONST9), 8: (4, CONST8),
          4: (8, b(z8)), 2: (1, b([d2v])), 7: (1, b([d7v])),
          10: (n10, b(z10)), 5: (1, b"\x00" * 4), 6: (1, b"\x00" * 4),
          1: (0, b""), 3: (0, b"")}
    return [(by[i][0], 0, by[i][1]) for i in ORDER]


def finex_body(descs, sec):
    """Run FinEx and return the 176-byte body of the stream that emitted the header."""
    ex = FinEx(sec, descs)
    ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = struct.unpack(">4I", make_header(sec))
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            return b"".join(struct.pack(">I", out.get((s_, k), 0)) for k in range(4, 48))
    return None


# body -> owning row index, from the blobs as recorded
body_owner = {}
for r in P3:
    raw = bytes.fromhex(r["blob"])
    body_owner.setdefault(raw[16:], []).append(r["i"])
print("distinct bodies among recorded blobs: %d" % len(body_owner), flush=True)

results = []
for r in P3:
    i = r["i"]
    raw = bytes.fromhex(r["blob"])
    got = finex_body(row_descs(A[i]), r["second"])
    if got is None:
        verdict = "no-header-stream"
        owner = None
    elif got == raw[16:]:
        verdict = "exact"
        owner = i
    else:
        owner = body_owner.get(got, [None])[0]
        verdict = "body-hits-row-%s" % owner
    results.append((i, verdict, owner, r["log"], r["nsign_ts"], r["blob"][:16]))
    print("[%2d] sec=%-11d %-12s blob=%s  -> %s" %
          (i, r["second"], r["log"], r["blob"][:16], verdict), flush=True)

print()
exact = [x for x in results if x[1] == "exact"]
mis = [x for x in results if x[1].startswith("body-hits")]
print("self-consistent rows: %d/%d" % (len(exact), len(results)))
print("mispaired rows      : %s" % ([x[0] for x in mis],))
json.dump([{"i": a, "verdict": b_, "owner": c, "log": d, "nsign_ts": e, "blob16": f}
           for a, b_, c, d, e, f in results],
          open(os.path.join(HERE, "audit_pairs_result.json"), "w"), indent=1)
print("saved audit_pairs_result.json")
