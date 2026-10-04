#!/usr/bin/env python -u
"""Scratch: split a d10 claim string into (key, value) using a candidate value
multiset, via exhaustive/greedy DP segmentation.  Ambiguity resolved by
reporting all segmentations and preferring the one whose key order matches a
law; every emitted value must be a verbatim map value."""
import re, json, os, sys, itertools
from collections import defaultdict

REV = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
sys.path.insert(0, REV)
from desc10_law import desc10_keys, build_desc10

B = json.load(open(os.path.join(REV, '_rv_blocks.json'), encoding='utf-8'))
SIGN = json.load(open(os.path.join(REV, 'all_signings.json'), encoding='utf-8'))

def mapdict(i):
    from _rv_extract import parse_map
    return dict(parse_map(B[i]['toString']))

CLICK_MAP = mapdict(1)   # genuine click map, 49 keys
SESS_MAP = mapdict(0)    # genuine session map, 50 keys

def d10(i):
    return bytes.fromhex(SIGN[i]['d10']).rstrip(b'\x00').decode('latin1')

# ---------------------------------------------------------------------------
# DP: segment S given a set of allowed tokens (values), returning all
# segmentations up to a cap.
def all_segs(s, toks, cap=2000):
    n = len(s)
    toks = sorted(set(toks), key=len, reverse=True)
    out = []
    def rec(pos, acc):
        if len(out) >= cap: return
        if pos == n:
            out.append(list(acc)); return
        for t in toks:
            if s.startswith(t, pos):
                acc.append(t)
                rec(pos + len(t), acc)
                acc.pop()
                if len(out) >= cap: return
    rec(0, [])
    return out

def segs_for(rowidx, m, label):
    s = d10(rowidx)
    vals = list(dict.fromkeys(m.values()))
    segs = all_segs(s, vals)
    print('--- row %d (%s): %d B, %d distinct map values, %d segmentations'
          % (rowidx, label, len(s), len(vals), len(segs)))
    return s, segs, vals

if __name__ == '__main__':
    for rowidx, m, label in ((8, CLICK_MAP, 'click'), (4, SESS_MAP, 'session'),
                             (3, CLICK_MAP, 'click+token'), (9, SESS_MAP, 'session2')):
        s, segs, vals = segs_for(rowidx, m, label)
        # print first 3 segmentations
        for k, sg in enumerate(segs[:3]):
            print('  seg%d (%d vals): %s' % (k, len(sg), '|'.join(sg)))
        print()
