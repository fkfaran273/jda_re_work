# att10_decode.py - decode the BIG desc10 variants (502 / 529 B).
#
# Why: desc10_law covers session (360 B) and click (387 B) only; 'attribution'
# raises "pending a capture". Every /attribution send in the campaign signed a
# SESSION-shaped 360 B claim set, so if the server rebuilds the claim set from an
# /attribution query and compares, our blobs could never match. all_signings
# contains 502 B and 529 B #10s - longer than both known kinds - so those are the
# candidate ATTRIBUTION (or event) claim sets. Decode them here.
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ALS = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))
G = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))

print('=== #10 lengths present in all_signings ===')
lens = {}
for s in ALS:
    if s.get('d10'):
        lens.setdefault(len(s['d10']) // 2, []).append(s)
for L in sorted(lens):
    print('  %4d B : %d signing(s)  src=%s'
          % (L, len(lens[L]), sorted({x.get('src') for x in lens[L]})))

print()
print('=== decode every distinct #10 as latin1 (values are plain concatenation) ===')
seen = set()
for L in sorted(lens):
    for s in lens[L]:
        h = s['d10']
        if h in seen:
            continue
        seen.add(h)
        txt = bytes.fromhex(h).decode('latin1')
        print('--- %d B ---' % L)
        print(txt)
        print()

# ---- anchor the genuine /attribution query values inside the big ones --------
q = G['query'].split('?', 1)[1]
import urllib.parse
val = {k: v[0] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}
print('=== genuine /attribution query keys (%d) ===' % len(val))
print(sorted(val))
print()
print('=== which query values appear in the 502/529 B #10s? ===')
for L in (502, 529):
    if L not in lens:
        continue
    txt = bytes.fromhex(lens[L][0]['d10']).decode('latin1')
    present = {k: (v in txt) for k, v in val.items()}
    inshape = [k for k, ok in present.items() if ok]
    print('  %d B: %d/%d query values found: %s' % (L, len(inshape), len(val), sorted(inshape)))
    missing = [k for k, ok in present.items() if not ok]
    print('        values NOT found verbatim: %s' % sorted(missing))
print()
print('=== law keys for comparison ===')
import sys
sys.path.insert(0, HERE)
from desc10_law import desc10_keys
for kind in ('session', 'click'):
    print('  %-8s %d keys: %s' % (kind, len(desc10_keys(kind)), desc10_keys(kind)))