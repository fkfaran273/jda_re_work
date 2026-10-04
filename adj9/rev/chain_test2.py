# chain_test2.py - do the 10 signings relate to each other? (hash chain / counter)
import itertools
import json
import os
import struct

REV = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(REV, 'all_signings.json'), encoding='utf-8'))


def fresh(d0hex):
    w = list(struct.unpack('>36I', bytes.fromhex(d0hex)))
    p = None
    for cand in range(1, 18):
        if all(w[x] == w[x - cand] for x in range(cand + 1, 36)):
            p = cand
            break
    pref = struct.pack('>I', w[0])
    if p is None:
        return pref, b''.join(struct.pack('>I', v) for v in w[1:])
    tile = b''.join(struct.pack('>I', v) for v in w[1:1 + p])
    return pref, tile


S = []
for k, s in enumerate(A):
    pref, tile = fresh(s['d0'])
    S.append(dict(k=k, src=s['src'], pref=pref, tile=tile,
                  d2=bytes.fromhex(s['d2']), d4=bytes.fromhex(s['d4']),
                  d0=bytes.fromhex(s['d0']), d10=bytes.fromhex(s['d10'])))

print('=== self-relations (same signing) ===')
for s in S:
    rel = []
    for nm, v in (('d2', s['d2']), ('pref', s['pref']), ('tile', s['tile'])):
        if v in s['d4']:
            rel.append('%s in d4' % nm)
        if v in s['d0']:
            rel.append('%s in d0' % nm)
        if len(v) <= 16 and v in s['d10']:
            rel.append('%s in d10' % nm)
    print('  S%-2d %s' % (s['k'], ', '.join(rel) or 'none'))

print()
print('=== cross-relations: does S_k field appear inside S_j field? ===')
names = ('pref', 'tile', 'd2', 'd4', 'd0', 'd10')
found = []
for s, t in itertools.permutations(S, 2):
    for an in names:
        a = s[an]
        if len(a) > 40:
            continue
        for bn in names:
            if a in t[bn]:
                found.append('S%d.%s (%dB) inside S%d.%s'
                             % (s['k'], an, len(a), t['k'], bn))
for f in found[:40]:
    print('  ' + f)
print('  total cross-hits: %d' % len(found))
if not found:
    print('  NONE - no field of any signing appears in any other signing')

print()
groups = {}
for s in S:
    groups.setdefault(s['src'], []).append(s['k'])
print('=== adjacency test (16B windows) within same capture ===')
for src, ks in groups.items():
    for a, b in zip(ks, ks[1:]):
        sa = [x for x in S if x['k'] == a][0]
        sb = [x for x in S if x['k'] == b][0]
        hits = []
        for wn, w in (('d4', sb['d4']), ('d0', sb['d0']), ('d10', sb['d10'])):
            for off in range(0, max(0, len(w) - 15)):
                if w[off:off + 16] in sa['d4'] or w[off:off + 16] in sa['d0']:
                    hits.append('%s[%d:16] of S%d in S%d' % (wn, off, b, a))
        print('  S%d -> S%d : %s' % (a, b, hits or 'no 16B linkage'))