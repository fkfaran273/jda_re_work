"""bodymatch.py - THE pairing gate for the whole derivation (slice 136).

Claim: the VM's 44-word BODY is descriptor-only (second-independent).
If true, each of the 10 all_signings rows body-matches exactly one of the
captured nsign blobs regardless of the second FinEx is seeded with.

This gives sound (row -> blob -> nsign_ts -> second) pairs, and resolves
whether the 7/8/9 triplet shares a second.

Steps:
 0. sanity: same descriptors + two different seconds -> same body?
 1. for each of the 10 rows: build full descriptors, FinEx, take body dwords.
 2. load the blobs (pair_h3.json 8 + extract any more from adj9_wh*.log).
 3. match each row body against each blob body; require exactly-one hits.
 4. report: table row -> blob idx -> second, plus the 7/8/9 verdict.
"""
import base64
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


def finex_body(descs, sec):
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
        return None, st, ex.steps
    got = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
    return got, st, ex.steps


def blob_body(blobhex):
    raw = bytes.fromhex(blobhex)
    return raw[16:]          # skip 16-B header, keep 44-word body


print("=== step 0: second-independence sanity (row 0, sec A vs sec B) ===")
d0 = row_descs(A[0])
gA, stA, stepsA = finex_body(d0, 1789903463)
gB, stB, stepsB = finex_body(d0, 1000000000)
print("  secA status=%s steps=%d got=%s" % (stA, stepsA, "ok" if gA else "NO-STREAM"))
print("  secB status=%s steps=%d got=%s" % (stB, stepsB, "ok" if gB else "NO-STREAM"))
if gA and gB:
    print("  bodyA == bodyB: %s" % (gA[16:] == gB[16:]))
    print("  hdrA  == hdrB : %s" % (gA[:16] == gB[:16]))
    SAME_BODY = (gA[16:] == gB[16:])
else:
    SAME_BODY = False
    print("  SANITY FAILED - cannot proceed to matching")
print()

if not SAME_BODY:
    print("BODY IS SECOND-DEPENDENT - the descriptor-only claim is FALSE.")
    print("Falling back to per-second FinEx arms (slower path).")
    sys.exit(2)

print("=== step 1: bodies for all 10 rows (single probe second) ===")
PROBE = 1789903463
rowbodies = []
for i, row in enumerate(A):
    got, st, steps = finex_body(row_descs(row), PROBE)
    body = got[16:] if got else None
    rowbodies.append(body)
    print("  row %d d2=%s status=%-10s steps=%-9d %s" %
          (i, row["d2"], st, steps, "ok %s..." % body[:8].hex() if body else "NO-BLOB"))
print()

print("=== step 2: blob bodies (pair_h3 8) ===")
blobs = [(r["i"], r["second"], r["blob"], r.get("nsign_ts")) for r in P3]
for i, sec, bh, ts in blobs:
    print("  blob idx=%d second=%d ts=%s head=%s" % (i, sec, ts, bh[:16]))
print()

print("=== step 3: match table (row -> blob by body equality) ===")
pairs = {}
for ri, rb in enumerate(rowbodies):
    if rb is None:
        print("  row %d: NO-BODY (FinEx failed)" % ri)
        continue
    hits = [bi for bi, (pi, sec, bh, ts) in enumerate(blobs) if blob_body(bh) == rb]
    if len(hits) == 1:
        bi = hits[0]
        pi, sec, bh, ts = blobs[bi]
        pairs[ri] = (pi, sec, ts)
        print("  row %d (d2=%s) -> blob idx %d (pair_h3 i=%d) second=%d ts=%s" %
              (ri, A[ri]["d2"], bi, pi, sec, ts))
    elif len(hits) == 0:
        print("  row %d (d2=%s) -> NO MATCH among 8 blobs" % (ri, A[ri]["d2"]))
    else:
        print("  row %d (d2=%s) -> AMBIGUOUS %s" % (ri, A[ri]["d2"], hits))
print()
print("=== step 4: verdicts ===")
print("matched: %d / 10 rows" % len(pairs))
# 7/8/9 triplet
for r in (7, 8, 9):
    if r in pairs:
        print("  row %d -> second %d" % (r, pairs[r][1]))
    else:
        print("  row %d -> UNMATCHED" % r)
if 7 in pairs and 8 in pairs and 9 in pairs:
    s7, s8, s9 = pairs[7][1], pairs[8][1], pairs[9][1]
    print("  triplet seconds: %d %d %d  all-equal=%s" % (s7, s8, s9, s7 == s8 == s9))
json.dump({str(k): {"pair_i": v[0], "second": v[1], "nsign_ts": v[2]}
           for k, v in pairs.items()},
          open(os.path.join(HERE, "bodymatch.json"), "w"), indent=1)
print("saved bodymatch.json")
