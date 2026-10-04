# corpus_pair_audit.py - which captured signings can be paired UNambiguously?
#
# corpus_e2e.py paired 8 samples to 6 blobs and got 6/8 byte-exact; the two
# mismatches were samples whose own blob is absent from the corpus, so they fell
# back onto the golden blob. This audit reports the claim structure WITHOUT any VM
# runs, so the verification count can be stated precisely.
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
sys.path.insert(0, HERE)
from header_gen import make_header

ALS = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))
NSIGN_RE = re.compile(r'###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n'
                      r'text: len=\d+\nnano_out=\d+\nhex=([0-9a-f]+)')
index = {}
for fn in ('adj9_wh.log', 'adj9_wh2.log', 'adj9_wh4.log'):
    p = os.path.join(DEV, fn)
    if not os.path.exists(p):
        continue
    for _ts, hx in NSIGN_RE.findall(open(p, 'rb').read().decode('utf-8', 'replace')):
        b = bytes.fromhex(hx)
        index.setdefault(b[:16], b)
print('blobs indexed by header: %d' % len(index))

ISO_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}')


def wall_second(ca):
    import calendar
    import datetime
    dt = datetime.datetime.strptime(ca[:19], '%Y-%m-%dT%H:%M:%S')
    off = ca[-5:]
    sgn = 1 if off[0] == '+' else -1
    return calendar.timegm(dt.timetuple()) - sgn * (int(off[1:3]) * 3600 +
                                                   int(off[3:5]) * 60)


claims = {}
for i, s in enumerate(ALS):
    if not s.get('d10'):
        continue
    m = ISO_RE.search(bytes.fromhex(s['d10']).decode('latin1'))
    if not m:
        continue
    ws = wall_second(m.group(0))
    hit = None
    for cand in (ws, ws + 1, ws + 2, ws - 1, ws + 3, ws - 2):
        if make_header(cand) in index:
            hit = (cand, index[make_header(cand)][:16])
            break
    claims.setdefault(hit, []).append((i, len(s['d10']) // 2, ws))

print()
print('=== blob claims (a blob claimed by >1 sample means the others\' own '
      'blobs are absent) ===')
for key in sorted(claims, key=lambda k: (k is None, k)):
    v = claims[key]
    if key is None:
        print('  NO BLOB: samples %s' % [(i, f'#10={n}B') for i, n, _ in v])
        continue
    sec, head = key
    tag = 'UNIQUE' if len(v) == 1 else 'SHARED by %d' % len(v)
    print('  sec=%-11d blob=%s…  %-12s samples=%s'
          % (sec, head.hex()[:8], tag, [(i, f'#10={n}B') for i, n, _ in v]))
print()
uniq = [v[0] for k, v in claims.items() if k and len(v) == 1]
print('unambiguous pairs: %d -> %s' % (len(uniq), [(i, f'#10={n}B') for i, n, _ in uniq]))
print('ambiguous samples (own blob missing): %s'
      % [(i, f'#10={n}B') for k, v in claims.items() if k and len(v) > 1
         for i, n, _ in v[1:]])