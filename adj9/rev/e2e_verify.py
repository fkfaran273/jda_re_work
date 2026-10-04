# e2e_verify.py - extend the byte-exact end-to-end check beyond the one golden
# session signing.
#
# Until now FinEx was verified 48/48 on ONE signing (the 360 B session golden).
# all_signings.json holds full descriptor sets (d0,d9,d8,d4,d2,d7,d10,d5,d6) for
# 11 signings across 4 #10 lengths and BOTH kinds, and wh4_records.nsigns holds
# captured blobs whose second is recoverable from the header law. Pair them and
# run the VM: anything that reproduces its captured blob byte-exactly extends the
# proof to that kind/length.
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

ORDER = json.load(open(os.path.join(HERE, 'adj9_material.json')))['va_order']
FD = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
W = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
ALS = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))
CONST8 = bytes.fromhex('bffffffffffffd1f0007000000000000')
CONST9 = bytes.fromhex('fad0f10d60f93c17937b2f1eb6c09691ae7d74bd')


def hbytes(v):
    if isinstance(v, dict):
        for k in ('hex', 'data_hex', 'value'):
            if k in v:
                return hbytes(v[k])
    if isinstance(v, list):
        return bytes(v)
    return bytes.fromhex(str(v).replace('0x', '').strip())


# ---- captured blobs -> header-law seconds -----------------------------------
blobs = []
for i, n in enumerate(W['nsigns']):
    b = hbytes(n)
    sec = None
    for cand in range(1789238000, 1789250000):
        if make_header(cand) == b[:16]:
            sec = cand
            break
    blobs.append((i, b, sec))
print('captured blobs: %d' % len(blobs))
for i, b, sec in blobs:
    print('  nsigns[%d] %dB head=%s sec=%s' % (i, len(b), b[:8].hex(), sec))
print()


def wall_second(created_at):
    import calendar
    import datetime
    if not created_at:
        return None
    dt = datetime.datetime.strptime(created_at[:19], '%Y-%m-%dT%H:%M:%S')
    off = created_at[-5:]
    sgn = 1 if off[0] == '+' else -1
    return calendar.timegm(dt.timetuple()) - sgn * (int(off[1:3]) * 3600 +
                                                   int(off[3:5]) * 60)


# ---- pair samples to blobs --------------------------------------------------
ISO_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}')
pairs, amb = [], []
for i, s in enumerate(ALS):
    if not s.get('d10'):
        continue
    txt = bytes.fromhex(s['d10']).decode('latin1')
    m = ISO_RE.search(txt)
    ws = wall_second(m.group(0)) if m else None
    cands = [(bi, b, sec) for bi, b, sec in blobs if sec and ws and abs(sec - ws) <= 3]
    if len(cands) == 1:
        pairs.append((i, s, cands[0]))
    elif cands:
        amb.append((i, ws, [c[0] for c in cands]))
print('pairs found: %d   ambiguous: %s' % (len(pairs), amb))
for i, s, (bi, b, sec) in pairs:
    print('  als[%d] (#10=%dB src=%s) -> nsigns[%d] sec=%d'
          % (i, len(s['d10']) // 2, s.get('src'), bi, sec))
print()


def blob_of(sample, second):
    by = {0: (36, bytes.fromhex(sample['d0'])),
          9: (5, CONST9), 8: (4, CONST8),
          4: (8, bytes.fromhex(sample['d4'])),
          2: (1, bytes.fromhex(sample['d2'])),
          7: (1, bytes.fromhex(sample['d7'])),
          10: (len(bytes.fromhex(sample['d10'])) // 4, bytes.fromhex(sample['d10'])),
          5: (1, bytes.fromhex(sample['d5'])),
          6: (1, bytes.fromhex(sample['d6'])),
          1: (0, b''), 3: (0, b'')}
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in ORDER])
    st = ex.run(max_steps=20_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = struct.unpack('>4I', make_header(second))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    if stream is None:
        return st, ex.steps, b''
    return st, ex.steps, b''.join(struct.pack('>I', out.get((stream, k), 0))
                                  for k in range(48))


print('=== end-to-end VM reproduction per captured signing ===')
results = []
for i, s, (bi, blob, sec) in pairs:
    kind = 'click' if len(s['d10']) // 2 in (388, 532) else 'session'
    st, steps, got = blob_of(s, sec)
    same = got == blob
    nd = sum(1 for k in range(48)
             if got[k * 4:k * 4 + 4] != blob[k * 4:k * 4 + 4]) if got else 48
    print('  als[%-2d] %-7s #10=%-3dB nsigns[%d] status=%-11s steps=%-9d %s (diff %d/48)'
          % (i, kind, len(s['d10']) // 2, bi, st, steps,
             'BYTE-EXACT' if same else 'MISMATCH', nd))
    results.append((i, kind, len(s['d10']) // 2, same))

ok = sum(1 for r in results if r[3])
print('\n=== RESULT: %d/%d captured signings reproduced byte-exactly ===' % (ok, len(results)))
json.dump([{'als': r[0], 'kind': r[1], 'd10_len': r[2], 'byte_exact': r[3]}
           for r in results],
          open(os.path.join(HERE, 'e2e_verify_result.json'), 'w'), indent=1)