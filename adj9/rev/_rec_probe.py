"""_rec_probe.py — record-level diff probes for corpus row 7.

For each variant, run FinEx, extract the 144-byte record (first-write at
offsets 1134..1277 of stream 0x5450001000) and the 176-byte body, and diff
both vs the base run.  Reveals (a) which region words feed which record
bytes, (b) how a record byte flip propagates into the body.
"""
import json
import struct
import sys
import time
from multiprocessing import Pool

sys.path.insert(0, '.')
import mint_pipeline as M
from fin_vm2 import FinEx

ROW = 7
MAIN = 0x5450001000
REC_OFF = 1134
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
rows = json.load(open('all_signings.json', encoding='utf-8'))
pairs = json.load(open('pair_h3.json', encoding='utf-8'))
r, p = rows[ROW], pairs[ROW]
sec = p['second']
d0w0 = list(struct.unpack('>36I', bytes.fromhex(r['d0'])))
d2w0 = struct.unpack('>I', bytes.fromhex(r['d2']))[0]
d4w0 = list(struct.unpack('>8I', bytes.fromhex(r['d4'])))
claims = bytes.fromhex(r['d10'])
unp = len(claims)
padded = claims + b'\x00' * ((-unp) % 4)


def mk(d0w, d2w, d4w):
    d0 = b''.join(struct.pack('>I', w & 0xFFFFFFFF) for w in d0w)
    d2 = struct.pack('>I', d2w & 0xFFFFFFFF)
    d4 = b''.join(struct.pack('>I', w & 0xFFFFFFFF) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unp)),
          10: (len(padded) // 4, 0, padded), 5: (1, 0, b"\0" * 4),
          6: (1, 0, b"\0" * 4), 1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in M.VA_ORDER]


def run(job):
    name, d0w, d2w, d4w = job
    ex = FinEx(sec, mk(d0w, d2w, d4w))
    ex.__dict__["_emit_full"] = []
    st = ex.run(max_steps=60_000_000)
    rec = {}
    for (pc, sva, top, n, v) in ex.__dict__["_emit_full"]:
        if (sva & 0xFFFFFFFFFFFF) == MAIN:
            o = top + n
            if o not in rec:
                rec[o] = v & 0xFF
    record = bytes(rec[REC_OFF + i] for i in range(144))
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n)] = v & 0xFFFFFFFF
    body = b"".join(struct.pack(">I", last.get((0x5500000000, k), 0))
                    for k in range(4, 48))
    return name, record, body, st


PROBES = [
    ("base", d0w0, d2w0, d4w0),
    ("d4_4^1", d0w0, d2w0, d4w0[:4] + [d4w0[4] ^ 1] + d4w0[5:]),
    ("d4_4^0x100", d0w0, d2w0, d4w0[:4] + [d4w0[4] ^ 0x100] + d4w0[5:]),
    ("d2^1", d0w0, d2w0 ^ 1, d4w0),
    ("d2^0x100", d0w0, d2w0 ^ 0x100, d4w0),
    ("d0_0^1", [d0w0[0] ^ 1] + d0w0[1:], d2w0, d4w0),
    ("d0_4^1", d0w0[:4] + [d0w0[4] ^ 1] + d0w0[5:], d2w0, d4w0),
    ("d4_0^1", d0w0, d2w0, [d4w0[0] ^ 1] + d4w0[1:]),
]

if __name__ == '__main__':
    t0 = time.time()
    with Pool(6) as pool:
        res = pool.map(run, PROBES)
    print("all runs done in %.0fs" % (time.time() - t0))
    base = dict((n, (rec, bod)) for n, rec, bod, _ in res
                if n == "base")[ "base"]
    out = {}
    for name, rec, bod, st in res:
        br, bb = base
        dr = [i for i in range(144) if rec[i] != br[i]]
        db = [i for i in range(176) if bod[i] != bb[i]]
        print("%-12s st=%s recdiff=%d %s" % (name, st, len(dr), dr[:20]))
        print("             bodydiff=%d %s" % (len(db), db[:20]))
        out[name] = {"record": rec.hex(), "body": bod.hex(),
                     "recdiff": dr, "bodydiff": db}
    json.dump(out, open('_rec_probe_row7.json', 'w'), indent=1)
    print("wrote _rec_probe_row7.json")
