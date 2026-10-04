"""blob_word_gate.py - THE decisive test.

Entry 0 (golden, d2=fb1a8296) and entry 2 (d2=4bce691e) share sec=1789240512 and
byte-identical 360-B claims, but have different regions. FinEx both at that second:
- words IDENTICAL in both outputs = determined by (claims,second) -> server-verifiable
- words DIFFERENT = depend on the random region -> not verifiable
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
CONST8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
CONST9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


def row_descs(row):
    z36 = list(struct.unpack(">36I", bytes.fromhex(row["d0"])))
    z8 = list(struct.unpack(">8I", bytes.fromhex(row["d4"])))
    d2v = int(row["d2"], 16)
    d7v = int(row["d7"], 16)
    raw10 = bytes.fromhex(row["d10"])
    n10 = len(raw10) // 4
    z10 = list(struct.unpack(">%dI" % n10, raw10))
    by = {0: (36, b(z36)), 9: (5, bytes.fromhex(row["d9"])), 8: (4, bytes.fromhex(row["d8"])),
          4: (8, b(z8)), 2: (1, b([d2v])), 7: (1, b([d7v])),
          10: (n10, b(z10)), 5: (1, b"\x00" * 4), 6: (1, b"\x00" * 4),
          1: (0, b""), 3: (0, b"")}
    return [(by[i][0], 0, by[i][1]) for i in ORDER]


def finex_blob(descs, sec):
    ex = FinEx(sec, descs)
    ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = struct.unpack(">4I", make_header(sec))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    return (b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
            if stream is not None else None)


BYD2 = {r["d2"]: r for r in A}
r0 = BYD2["fb1a8296"]
r2 = BYD2["4bce691e"]
sec = 1789240512
print("row0 d0 W0=%s d2=%s" % (r0["d0"][:8], r0["d2"]), flush=True)
print("row2 d0 W0=%s d2=%s" % (r2["d0"][:8], r2["d2"]), flush=True)

b0 = finex_blob(row_descs(r0), sec)
b2 = finex_blob(row_descs(r2), sec)
print("both blobs computed", flush=True)
w0 = struct.unpack(">48I", b0)
w2 = struct.unpack(">48I", b2)
same = [i for i in range(48) if w0[i] == w2[i]]
diff = [i for i in range(48) if w0[i] != w2[i]]
print("SAME words (%d/48): %s" % (len(same), same))
print("DIFF words (%d/48): %s" % (len(diff), diff))
for i in same:
    print("  [%2d] %08x (server-verifiable)" % (i, w0[i]), flush=True)
json.dump({"same": same, "diff": diff},
          open(os.path.join(HERE, "word_gate.json"), "w"), indent=1)
