# sec_scan.py - pin each trace signing's TRUE call second: make_header(sec) is a
# deterministic 4-dword pattern, so scan every sink's pos0..3 for a header match.
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

DEV = os.path.join(os.path.dirname(HERE), 'device')
evs = [e for e in json.load(open(os.path.join(DEV, 'whcap_hits7.json'),
                                 encoding='utf-8')) if e.get('tag') == 'emit']
sinks = {}
for idx, e in enumerate(evs):
    sinks.setdefault(e['sink'], {})[int(e['pos'], 16)] = (int(e['val'], 16), idx)

print('sinks:', len(sinks), 'events:', len(evs))
print('--- scanning make_header(sec) against every sink window (sec 1789240300..1789240560) ---')
hits = []
for sec in range(1789240300, 1789240561):
    hdr = list(struct.unpack('>4I', make_header(sec)))
    for sk, pm in sinks.items():
        got = [pm.get(k, (None,))[0] for k in range(4)]
        if got == hdr:
            first_ev = min(pm.get(k, (0, 0))[1] for k in range(4))
            hits.append((sec, sk, first_ev))
for sec, sk, fe in sorted(hits, key=lambda x: x[2]):
    print('  sec=%d sink=%s first_ev=%d' % (sec, sk[-6:], fe))
print('distinct seconds with a header stream:', sorted({s for s, _, _ in hits}))