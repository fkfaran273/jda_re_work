# sens_test.py - which descriptors influence the body output?
# baseline = signing A (fin_descs.json, seed 1789240512, 48/48 known).
# Flip each descriptor and count body-dword diffs vs baseline.
import json, struct, sys, os, copy
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
D = json.load(open(HERE + '/fin_descs.json'))
SEED = 1789240512
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]

def run(descs):
    ex = FinEx(SEED, descs)
    ex.run(max_steps=20_000_000)
    sinks = {}
    for (sn, n, v) in ex.emit_trace:
        sinks.setdefault(sn, {})[n] = v
    return [sinks.get(0x5500000000, {}).get(i, 0) for i in range(48)]

def flip(data, nbits=1):
    b = bytearray(data)
    for i in range(min(nbits, len(b))):
        b[i] ^= 0x01
    return bytes(b)

def descs_with(idx, newdata, lens=None):
    by = {d['build_idx']: [d['len_dw'], bytes.fromhex(d['data_hex'])] for d in D['descs']}
    if lens is not None:
        by[idx][0] = lens
    by[idx][1] = newdata
    return [(by[i][0], 0, by[i][1]) for i in ORDER]

base_descs = [(d['len_dw'], 0, bytes.fromhex(d['data_hex'])) for d in
              sorted(D['descs'], key=lambda d: ORDER.index(d['build_idx']))]
# careful: FinEx expects descs in VA order; rebuild via by-dict in ORDER
by0 = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex'])) for d in D['descs']}
base_descs = [(by0[i][0], 0, by0[i][1]) for i in ORDER]
print('running baseline...', flush=True)
base = run(base_descs)
print('baseline out[4:12]:', [hex(x) for x in base[4:12]], flush=True)

variants = [
    ('H   bit0 flip   (#4)', 4, lambda d: flip(d, 1), None),
    ('#10 first byte   (#10)', 10, lambda d: flip(d, 1), None),
    ('#0  all zeros    (#0)', 0, lambda d: bytes(144), 36),
    ('#0  bit0 flip    (#0)', 0, lambda d: flip(d, 1), None),
    ('#9  bit0 flip    (#9)', 9, lambda d: flip(d, 1), None),
    ('#2  bit0 flip    (#2)', 2, lambda d: flip(d, 1), None),
    ('#5  zero         (#5)', 5, lambda d: bytes(4), 1),
    ('#6  zero         (#6)', 6, lambda d: bytes(4), 1),
]
for name, idx, fn, lens in variants:
    d2 = descs_with(idx, fn(by0[idx][1]), lens)
    out = run(d2)
    nd = sum(1 for i in range(48) if out[i] != base[i])
    print('%-24s -> body diff %d/48 %s' % (name, nd, '(AFFECTS BODY)' if nd else '(identity - safe to fabricate)'), flush=True)
print('SENS DONE', flush=True)
