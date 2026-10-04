"""d2_wire.py - first wire-op divergence between base and d2^1 (identical
control path, so logs align 1:1).  Localizes the queue op where d2's value
first influences data, and the CAP/POP context around it."""
import json
import struct
import sys
import time

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


def wire(d2w_):
    d0 = b''.join(struct.pack('>I', w) for w in d0w)
    d2 = struct.pack('>I', d2w_ & 0xFFFFFFFF)
    d4 = b''.join(struct.pack('>I', w) for w in d4w)
    ex = FinEx(sec, mk(d0, d2, d4))
    ex._wire_log = []
    ex.run(max_steps=60_000_000)
    return ex._wire_log


t = time.time()
wb = wire(d2w)
wp = wire(d2w ^ 1)
print("wire ops: base=%d probe=%d (%.0f s)" % (len(wb), len(wp),
                                               time.time() - t), flush=True)
k = 0
while k < min(len(wb), len(wp)) and wb[k] == wp[k]:
    k += 1
print("first divergent wire op at index %d" % k)
for j in range(max(0, k - 6), min(len(wb), k + 7)):
    mark = '>>' if j == k else '  '
    print("%s [%d] base=%s probe=%s" % (mark, j, wb[j], wp[j]))
out = {'first_divergence': k,
       'context_base': [list(map(str, e)) for e in wb[max(0, k - 20):k + 20]],
       'context_probe': [list(map(str, e)) for e in wp[max(0, k - 20):k + 20]],
       'n_ops': len(wb)}
json.dump(out, open('d2_wire.json', 'w'), indent=1)
print("saved d2_wire.json", flush=True)
