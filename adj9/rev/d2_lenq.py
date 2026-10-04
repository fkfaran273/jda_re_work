"""d2_lenq.py (standalone) - LENQ read PCs for d2/d4 streams + d4[4] threshold
bracketing probes (base-1, 0x250000)."""
import json
import struct
import sys
import time
from collections import Counter

sys.path.insert(0, '.')
from fin_vm2 import FinEx
import mint_pipeline as M

rows = json.load(open('all_signings.json', encoding='utf-8'))
pairs = {r['i']: r for r in json.load(open('pair_h3.json', encoding='utf-8'))}
r = rows[7]
sec = pairs[7]['second']
d0w = list(struct.unpack('>36I', bytes.fromhex(r['d0'])))
d2w = struct.unpack('>I', bytes.fromhex(r['d2']))[0]
d4w = list(struct.unpack('>8I', bytes.fromhex(r['d4'])))
claims = bytes.fromhex(r['d10'])
unp = len(claims)
padded = claims + b'\x00' * ((-unp) % 4)
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")


def mk(d0, d2, d4):
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unp)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in M.VA_ORDER]


def run(d2w_, d4w_, log=False):
    d0 = b''.join(struct.pack('>I', w) for w in d0w)
    d2 = struct.pack('>I', d2w_ & 0xFFFFFFFF)
    d4 = b''.join(struct.pack('>I', w) for w in d4w_)
    ex = FinEx(sec, mk(d0, d2, d4))
    if log:
        ex._lenq_log = []
        ex._emit_full = []
    ex.run(max_steps=60_000_000)
    return ex


out = {}

# ---- pass 1: base with LENQ log ----
ex = run(d2w, d4w, log=True)
lenqs = ex._lenq_log
print("total LENQ logged:", len(lenqs))
if lenqs:
    print("sample tuple:", [hex(x) if isinstance(x, int) else x
                            for x in lenqs[0]])
for target, label in ((0x5500004000, 'd2'), (0x5500003000, 'd4')):
    hits = [(k, e) for k, e in enumerate(lenqs) if (e[1] & 0xFFFFFFFFFFFF) == target]
    print("%s stream LENQ reads: %d" % (label, len(hits)))
    for k, e in hits[:10]:
        print("   emit-trace-idx~%d pc=%s n=%d val=%08x"
              % (k, hex(e[0]), e[2], e[4] & 0xFFFFFFFF))
    out['%s_lenq' % label] = [[k, hex(e[0]), e[2], e[4] & 0xFFFFFFFF]
                              for k, e in hits]

# ---- pass 2/3: d4[4] threshold bracketing ----
base_blob = None
for tag, v4 in (('m1', d4w[4] - 1), ('thr', 0x00250000),
                ('p1', d4w[4] + 1)):
    t = time.time()
    e2 = run(d2w, d4w[:4] + [v4 & 0xFFFFFFFF] + d4w[5:])
    last = {}
    for (sva, n, v) in e2.emit_trace:
        if (sva & 0xFFFFFFFFFFFF) == 0x5500000000:
            last[n] = v
    blob = b''.join(struct.pack('>I', last.get(k, 0)) for k in range(48))
    if base_blob is None:
        b0 = run(d2w, d4w)
        last0 = {}
        for (sva, n, v) in b0.emit_trace:
            if (sva & 0xFFFFFFFFFFFF) == 0x5500000000:
                last0[n] = v
        base_blob = b''.join(struct.pack('>I', last0.get(k, 0))
                             for k in range(48))
    same_as_base = (blob == base_blob)
    print("d4[4]=%08x -> steps=%d blob==base: %s (%.0f s)"
          % (v4 & 0xFFFFFFFF, e2.steps, same_as_base, time.time() - t),
          flush=True)
    out['d4_4_%s' % tag] = {'val': '%08x' % (v4 & 0xFFFFFFFF),
                            'steps': e2.steps, 'same_as_base': same_as_base,
                            'blob': blob.hex()}

json.dump(out, open('d2_lenq.json', 'w'), indent=1)
print("saved d2_lenq.json", flush=True)
