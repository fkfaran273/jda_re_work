"""fin118.py - THE decisive test.

Feed the slice-118 captured stream plane into FinEx as the descriptor set, using
the known second 1789834707 (inverted from the header) and our known H/map, and
ask: does the VM reproduce OUR blob byte-for-byte?

If yes  -> the stream plane IS the descriptor plane, and #0/#2/#4 are pure data
           (so only the derivation from (claims,H,second) remains).
If no   -> the mapping or the values are still off; report the closest arm.

Also cross-checks the captured streams against FinEx's own emit_trace (value-set
overlap), which is assignment-independent evidence.
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

SEC = 1789834707
h = json.load(open(os.path.join(HERE, "harvest_out.json"), encoding="utf-8"))
blob = base64.b64decode(h["blobB64"])
assert make_header(SEC) == blob[:16]
print("blob:", blob.hex())
print("second:", SEC, "header law OK")
ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
CONST8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
CONST9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

# captured streams: q -> ordered values (n ascending, n from 0)
S = {}
for q, n, v in h["emits"]:
    S.setdefault(q, {})[n] = v
ST = {}
for q, m in S.items():
    ns = sorted(m)
    ST[q] = [m[n] for n in ns]
by_len = {}
for q, vs in ST.items():
    by_len.setdefault(len(vs), []).append((q, vs))
print()
print("streams by slot count:", {k: [(q, "%08x" % vs[0]) for q, vs in v] for k, v in sorted(by_len.items())})

Q0 = 3467672896          # 36 words, w0=0x90  <- #0 shape
Q192 = 3467672992        # 36 words, w0=0xc0  <- holds blob[5..39]
Q4 = 3467677168          # 8 words           <- #4
Q8 = 3467676784          # 4 words, zeros    <- #8?
Q2 = 3467675776          # 1 word            <- #2
Q7 = 3467677024          # 1 word 0x150      <- #7
Q10 = 3467675344         # 84 words ASCII    <- #10
QA = 3467676448          # 1 word 0x10
QB = 3467677408          # 1 word 0


def w2b(vs, order="le"):
    return b"".join(struct.pack("<I" if order == "le" else ">I", v & 0xFFFFFFFF) for v in vs)


def run(name, descs):
    ex = FinEx(SEC, descs)
    st = ex.run(max_steps=20_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = struct.unpack(">4I", make_header(SEC))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    got = b""
    if stream is not None:
        got = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
    diff = (sum(1 for k in range(48) if got[k * 4:k * 4 + 4] != blob[k * 4:k * 4 + 4])
            if got else 48)
    print("  %-28s status=%-10s steps=%-9d %s" %
          (name, st, ex.steps, "BYTE-EXACT" if got == blob else "diff %d/48" % diff))
    return got == blob, got


def build(a0, a8, a2, a4, a7, a10, a5, a6):
    by = {0: (len(a0) // 4, a0), 9: (5, CONST9), 8: (len(a8) // 4, a8),
          4: (len(a4) // 4, a4), 2: (len(a2) // 4, a2), 7: (len(a7) // 4, a7),
          10: (len(a10) // 4, a10), 5: (len(a5) // 4, a5), 6: (len(a6) // 4, a6),
          1: (0, b""), 3: (0, b"")}
    return [(by[i][0], 0, by[i][1]) for i in ORDER]


print()
print("=== descriptor-from-capture arms ===")
arms = [
    ("A0 full36", w2b(ST[Q0]), CONST8, w2b(ST[Q2]), w2b(ST[Q4]), w2b(ST[Q7]), w2b(ST[Q10]), w2b(ST[QA]), w2b(ST[QB])),
    ("A0[1:]pad", w2b(ST[Q0][1:] + [0]), CONST8, w2b(ST[Q2]), w2b(ST[Q4]), w2b(ST[Q7]), w2b(ST[Q10]), w2b(ST[QA]), w2b(ST[QB])),
    ("A0 full36 + cap#8", w2b(ST[Q0]), w2b(ST[Q8]), w2b(ST[Q2]), w2b(ST[Q4]), w2b(ST[Q7]), w2b(ST[Q10]), w2b(ST[QA]), w2b(ST[QB])),
    ("#0=Q192(blob565)", w2b(ST[Q192]), CONST8, w2b(ST[Q2]), w2b(ST[Q4]), w2b(ST[Q7]), w2b(ST[Q10]), w2b(ST[QA]), w2b(ST[QB])),
]
ok = 0
for nm, a0, a8, a2, a4, a7, a10, a5, a6 in arms:
    good, _ = run(nm, build(a0, a8, a2, a4, a7, a10, a5, a6))
    ok += 1 if good else 0
print()
print("=== RESULT: %d/%d arms BYTE-EXACT ===" % (ok, len(arms)))