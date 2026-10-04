#!/usr/bin/env python -u
"""Scratch 2: segment d10 claim strings. Token alphabet = union of every value
in BOTH genuine maps + regex-extracted dates/uuids/versions from the d10 itself.
DP enumerates ALL segmentations; we then test each against desc10_keys law."""
import re, json, os, sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
from desc10_law import desc10_keys

REV = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
B = json.load(open(os.path.join(REV, '_rv_blocks.json'), encoding='utf-8'))
SIGN = json.load(open(os.path.join(REV, 'all_signings.json'), encoding='utf-8'))
from _rv_extract import parse_map

MAPS = [dict(parse_map(B[i]['toString'])) for i in range(len(B))]

DATE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z[+-]\d{4}')
UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')

def d10(i):
    return bytes.fromhex(SIGN[i]['d10']).rstrip(b'\x00').decode('latin1')

def alphabet(s):
    toks = set()
    for m in MAPS:
        toks.update(v for v in m.values() if v)
    toks.update(DATE.findall(s))
    toks.update(UUID.findall(s))
    return toks

def all_segs(s, toks, cap=50000):
    n = len(s)
    toks = sorted({t for t in toks if t}, key=lambda t: (-len(t), t))
    out = []
    def rec(pos, acc):
        if len(out) >= cap: return
        if pos == n:
            out.append(tuple(acc)); return
        for t in toks:
            if s.startswith(t, pos):
                acc.append(t); rec(pos + len(t), acc); acc.pop()
                if len(out) >= cap: return
    rec(0, [])
    return out

def report(i, label, kind):
    s = d10(i)
    toks = alphabet(s)
    segs = all_segs(s, toks)
    print('=== row %d (%s) len=%d alphabet=%d segs=%d' % (i, label, len(s), len(toks), len(segs)))
    counts = {}
    for sg in segs:
        counts[sg] = counts.get(sg, 0) + 1
    print('  distinct segs:', len(counts))
    for sg in list(counts)[:10]:
        print('   n=%2d  %s' % (len(sg), ' | '.join(sg)))
    law = desc10_keys(kind)
    print('  law key order (%d):' % len(law))
    for n, k in enumerate(law):
        print('   %2d %s' % (n, k))
    return s, counts, law

if __name__ == '__main__':
    which = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if which in ('all', 'sess'):
        report(4, 'SESSION', 'session')
    if which in ('all', 'click'):
        report(8, 'CLICK', 'click')
