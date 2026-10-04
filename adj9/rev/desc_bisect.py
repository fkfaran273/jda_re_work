# desc_bisect.py - INPUT-SPACE bisection of the adj9 blob.
#
# Why this exists: every previous "what does the server check" test flipped bits
# in the OUTPUT blob (slice 92 bisect_flip: header bytes + body dwords 0..43 ->
# all Organic). Flipping the OUTPUT is not the same as changing a descriptor
# INPUT, because the body is a value-steered transform of the descriptors. So the
# question "which descriptor actually reaches the wire?" was never asked in
# input space.
#
# This builds the golden signing plus one-descriptor variants and reports, per
# variant, the emit status and exactly which of the 48 output dwords moved. The
# variants are then the material for the decisive server test: send each with a
# query whose claim set is IDENTICAL (slice 99 §8.2 proved the server rebuilds
# the claim set from the request), so the ONLY difference on the wire is the
# descriptor we changed.
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

ORDER = json.load(open(os.path.join(HERE, 'adj9_material.json')))['va_order']
D = json.load(open(os.path.join(HERE, 'fin_descs.json')))
GOLD_SEC = D['target']['second']
GOLD_BLOB = bytes.fromhex(D['target']['blob_hex'])
DET = json.load(open(os.path.join(HERE, 'desc_det_result.json')))

BASE = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex']))
        for d in D['descs']}
# desc_det_result holds the LIVE descriptor values for three signings; the third
# (session, sec 1789240512) is the golden one.
LIVE = [e for e in DET if e['kind'] == 'session']

print('golden second %d, blob %d B' % (GOLD_SEC, len(GOLD_BLOB)))
print('base descs: %s' % {k: v[0] for k, v in sorted(BASE.items())})
print()


def blob_of(desc_over, second):
    """Run FinEx over BASE + overrides, return (status, steps, blob48, stream)."""
    by = dict(BASE)
    by.update(desc_over)
    descs = [(by[i][0], 0, by[i][1]) for i in ORDER]
    ex = FinEx(second, descs)
    status = ex.run(max_steps=20_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    hdr = struct.unpack('>4I', make_header(second))
    stream = None
    for (s, n) in out:
        if tuple(out.get((s, k), 0) for k in range(4)) == hdr:
            stream = s
            break
    blob = b''
    if stream is not None:
        blob = b''.join(struct.pack('>I', out.get((stream, k), 0)) for k in range(48))
    return status, ex.steps, blob, stream


def dwords(b):
    return [b[i * 4:i * 4 + 4] for i in range(48)]


def compare(tag, status, steps, blob, ref):
    if not blob:
        print('%-26s status=%-11s steps=%-9d NO BLOB (no header-law stream)'
              % (tag, status, steps))
        return
    law = blob[:16] == make_header(GOLD_SEC)
    a, b = dwords(blob), dwords(ref)
    diff = [i for i in range(48) if a[i] != b[i]]
    print('%-26s status=%-11s steps=%-9d law=%-3s diff=%-2d/48 %s'
          % (tag, status, steps, 'OK' if law else 'BAD', len(diff),
             diff[:12] if diff else 'IDENTICAL'))


def descs_from_live(e):
    """desc_det_result stores EMITTED u32 values; memory holds the BE bytes."""
    def u32s(vals):
        return b''.join(struct.pack('>I', v & 0xffffffff) for v in vals)
    return {0: (36, u32s(e['d0'])), 9: (5, u32s(e['d9'])),
            8: (4, u32s(e['d8'])), 4: (8, u32s(e['d4'])),
            2: (1, u32s([e['d2']])), 7: (1, u32s([e['d7']])),
            10: BASE[10]}


def main():
    print('=== A. control: captured descriptors (fin_descs) ===')
    st, steps, blob, _ = blob_of({}, GOLD_SEC)
    compare('control', st, steps, blob, GOLD_BLOB)
    print('  control == captured blob : %s' % (blob == GOLD_BLOB))
    print()

    print('=== B. which live descriptor set is the golden signing? ===')
    matches = []
    for i, e in enumerate(LIVE):
        over = descs_from_live(e)
        st, steps, blob, _ = blob_of(over, GOLD_SEC)
        compare('live[%d]' % i, st, steps, blob, GOLD_BLOB)
        if blob == GOLD_BLOB:
            matches.append(i)
    print('  live index matching the golden blob: %s' % (matches or 'NONE'))
    print()

    if not matches:
        print('skipping variants: no live descriptor set reproduced the blob')
        return
    gold = descs_from_live(LIVE[matches[0]])

    print('=== C. INPUT-SPACE bisection (one descriptor changed per arm) ===')
    arms = {
        '#0 <- zeros(144)': {0: (36, bytes(144))},
        '#2 <- 0': {2: (1, bytes(4))},
        '#2 <- 0xdeadbeef': {2: (1, struct.pack('>I', 0xdeadbeef))},
        '#4 <- zeros(32)': {4: (8, bytes(32))},
        '#8 <- zeros(16)': {8: (4, bytes(16))},
        '#9 <- zeros(20)': {9: (5, bytes(20))},
    }
    others = [e['d4'] for e in DET if e['d4'] != LIVE[matches[0]]['d4']]
    if others:
        arms['#4 <- foreign captured H'] = {
            4: (8, b''.join(struct.pack('>I', v & 0xffffffff) for v in others[0]))}
    for tag, over in arms.items():
        o = dict(gold)
        o.update(over)
        st, steps, blob, _ = blob_of(o, GOLD_SEC)
        compare(tag, st, steps, blob, GOLD_BLOB)

    json.dump({'second': GOLD_SEC, 'golden_blob': GOLD_BLOB.hex(),
               'live_match': matches},
              open(os.path.join(HERE, 'desc_bisect_result.json'), 'w'), indent=1)
    print('\nsaved desc_bisect_result.json')


if __name__ == '__main__':
    main()