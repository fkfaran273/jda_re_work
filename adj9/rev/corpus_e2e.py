# corpus_e2e.py - pair EVERY captured signing with its own blob (from the large
# nsign corpora) and verify the VM reproduces each blob byte-exactly.
#
# Method: index blobs by their 16-byte header; for each sample recover its
# created_at wall second and test make_header(ws-3..ws+3) against the index. That
# is 7 header computations per sample instead of brute-forcing thousands, and it
# pairs strictly by the header law (no loose time windows).
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

ORDER = json.load(open(os.path.join(HERE, 'adj9_material.json')))['va_order']
ALS = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))
CONST8 = bytes.fromhex('bffffffffffffd1f0007000000000000')
CONST9 = bytes.fromhex('fad0f10d60f93c17937b2f1eb6c09691ae7d74bd')
NSIGN_RE = re.compile(r'###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n'
                      r'text: len=\d+\nnano_out=\d+\nhex=([0-9a-f]+)')

index = {}
counts = {}
for fn in ('adj9_wh.log', 'adj9_wh2.log', 'adj9_wh4.log', 'adj9_capture_full.log'):
    p = os.path.join(DEV, fn)
    if not os.path.exists(p):
        continue
    txt = open(p, 'rb').read().decode('utf-8', 'replace')
    recs = NSIGN_RE.findall(txt)
    for _ts, hx in recs:
        b = bytes.fromhex(hx)
        index.setdefault(b[:16], b)
    counts[fn] = len(recs)
print('nsign records scanned: %s' % counts)
print('distinct blobs indexed by header: %d' % len(index))
print()

ISO_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}')


def wall_second(ca):
    import calendar
    import datetime
    dt = datetime.datetime.strptime(ca[:19], '%Y-%m-%dT%H:%M:%S')
    off = ca[-5:]
    sgn = 1 if off[0] == '+' else -1
    return calendar.timegm(dt.timetuple()) - sgn * (int(off[1:3]) * 3600 +
                                                   int(off[3:5]) * 60)


def blob_of(sample, second):
    u10 = bytes.fromhex(sample['d10'])
    by = {0: (36, bytes.fromhex(sample['d0'])), 9: (5, CONST9), 8: (4, CONST8),
          4: (8, bytes.fromhex(sample['d4'])), 2: (1, bytes.fromhex(sample['d2'])),
          7: (1, bytes.fromhex(sample['d7'])), 10: (len(u10) // 4, u10),
          5: (1, bytes.fromhex(sample['d5'])), 6: (1, bytes.fromhex(sample['d6'])),
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


pairs = []
for i, s in enumerate(ALS):
    if not s.get('d10'):
        continue
    txt = bytes.fromhex(s['d10']).decode('latin1')
    m = ISO_RE.search(txt)
    if not m:
        continue
    ws = wall_second(m.group(0))
    for cand in (ws, ws + 1, ws + 2, ws - 1, ws + 3, ws - 2):
        hdr = make_header(cand)
        if hdr in index:
            pairs.append((i, s, cand, index[hdr]))
            break

print('pairs found: %d' % len(pairs))
for i, s, sec, b in pairs:
    print('  als[%-2d] #10=%-3dB sec=%-11d blob=%s…'
          % (i, len(s['d10']) // 2, sec, b[:8].hex()))
print()

print('=== end-to-end VM reproduction per captured signing ===')
res = []
for i, s, sec, blob in pairs:
    n10 = len(s['d10']) // 2
    kind = 'click' if n10 in (388, 532) else 'session'
    signed = 'token' if n10 in (504, 532) else 'plain'
    st, steps, got = blob_of(s, sec)
    same = got == blob
    diff = sum(1 for k in range(48)
               if got[k * 4:k * 4 + 4] != blob[k * 4:k * 4 + 4]) if got else 48
    print('  als[%-2d] %-7s %-5s #10=%-3dB sec=%-11d status=%-11s steps=%-9d %s'
          % (i, kind, signed, n10, sec, st, steps,
             'BYTE-EXACT' if same else 'MISMATCH diff %d/48' % diff))
    res.append({'als': i, 'kind': kind, 'token': signed, 'd10_len': n10,
                'sec': sec, 'status': st, 'steps': steps, 'byte_exact': same})

ok = sum(1 for r in res if r['byte_exact'])
print('\n=== RESULT: %d/%d paired signings reproduced byte-exactly ===' % (ok, len(res)))
json.dump(res, open(os.path.join(HERE, 'corpus_e2e_result.json'), 'w'), indent=1)