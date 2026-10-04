"""_rec_dump.py — one FinEx run on corpus row 7, full wire dump to JSON.

Captures per stream: every emit (pc, top, n, v) in order + LENQ reads, then the
final blob.  Cached to _rec_dump_row7.json for offline analysis.
"""
import json
import struct
import sys
import time

sys.path.insert(0, '.')
import mint_pipeline as M
from fin_vm2 import FinEx

ROW = int(sys.argv[1]) if len(sys.argv) > 1 else 7
OUT = sys.argv[2] if len(sys.argv) > 2 else '_rec_dump_row%d.json' % ROW

rows = json.load(open('all_signings.json', encoding='utf-8'))
pairs = json.load(open('pair_h3.json', encoding='utf-8'))
r, p = rows[ROW], pairs[ROW]
sec = p['second']
d0 = bytes.fromhex(r['d0']); d2 = bytes.fromhex(r['d2']); d4 = bytes.fromhex(r['d4'])
claims = bytes.fromhex(r['d10']); unp = len(claims)
padded = claims + b'\x00' * ((-unp) % 4)
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
      2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unp)),
      10: (len(padded)//4, 0, padded), 5: (1, 0, b"\0"*4), 6: (1, 0, b"\0"*4),
      1: (0, 0, b""), 3: (0, 0, b"")}
descs = [by[i] for i in M.VA_ORDER]

t0 = time.time()
ex = FinEx(sec, descs)
ex.__dict__["_emit_full"] = []
ex.__dict__["_lenq_log"] = []
ex.__dict__["_wire_log"] = []
st = ex.run(max_steps=60_000_000)
print("status", st, "steps", ex.steps, "%.0fs" % (time.time() - t0))

ef = ex.__dict__["_emit_full"]
streams = {}
for (pc, sva, top, n, v) in ef:
    streams.setdefault(sva & 0xFFFFFFFFFFFF, []).append(
        [pc, top, n, v & 0xFFFFFFFF])
last = {}
for (sva, n, v) in ex.emit_trace:
    last[(sva & 0xFFFFFFFFFFFF, n)] = v & 0xFFFFFFFF
blob = b"".join(struct.pack(">I", last.get((0x5500000000, k), 0))
                for k in range(48))
out = {"row": ROW, "second": sec, "status": st, "steps": ex.steps,
       "blob": blob.hex(),
       "streams": {"%d" % k: v for k, v in streams.items()},
       "lenq": ex.__dict__["_lenq_log"]}
json.dump(out, open(OUT, 'w'))
print("wrote", OUT, "streams:", {("%d" % k): len(v) for k, v in streams.items()})
