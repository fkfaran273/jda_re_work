# recog_probe.py - WHAT DOES THE SERVER RECOGNIZE? Uses the genuine captured body
# (fresh_genuine.json) and varies ONLY the 16-B header and the query params.
# Signal: HTTP 400 (ask_in...) = recognized+consumed; 200 + Organic = not
# recognized; 200 + real token = recognized+fresh. /attribution polls are not
# interval-limited (unsigned_result.json: attr1-3 all 200), so a 400 is specific.
import json
import os
import struct
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_full_chain as F
from header_gen import make_header

G = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))
GEN = bytes.fromhex(G['blob_hex'])
Q = urllib.parse.parse_qs(urllib.parse.urlsplit(G['query']).query)
print('genuine blob %d B  hdr=%s' % (len(GEN), GEN[:16].hex()))
print('genuine query keys (%d): %s' % (len(Q), sorted(Q)))

F.USE_DEVICE = True
F.NO_SIGN = False
now = int(time.time())


def q(**over):
    """copy of the genuine query, with overrides (None = drop the key)"""
    out = {}
    for k, v in Q.items():
        out[k] = v[0]
    for k, v in over.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


def blob_with_crafted_header(second):
    return make_header(second) + GEN[16:]


VARIANTS = [
    ('1 verbatim body+query (control)', GEN, q()),
    ('2 crafted header + genuine query', blob_with_crafted_header(now), q()),
    ('3 crafted hdr + pert. device_name', blob_with_crafted_header(now),
     q(device_name='pixel 7')),
    ('4 crafted hdr + extra param', blob_with_crafted_header(now),
     q(session_count='7')),
    ('5 crafted hdr + dropped ui_mode', blob_with_crafted_header(now),
     q(ui_mode=None)),
    ('6 crafted hdr + fresh android_uuid', blob_with_crafted_header(now),
     q(android_uuid='11111111-2222-3333-4444-555555555555')),
    ('7 crafted hdr + fresh created_at', blob_with_crafted_header(now),
     q(created_at='2026-09-17T23:59:59.000Z+0530')),
]

res = []
for label, blob, params in VARIANTS:
    code, body = F.send_device('https://app.adjust.com/attribution', params, blob,
                               method='GET')
    short = body.strip().replace('\r\n', '')[:200]
    print('%-38s -> HTTP %s  %s' % (label, code, short), flush=True)
    res.append({'label': label, 'http': code, 'body': short,
                'header': blob[:16].hex()})
    time.sleep(2)
json.dump(res, open(os.path.join(HERE, 'recog_probe_result.json'), 'w'), indent=1)
print('saved recog_probe_result.json')
print()
print('READ: HTTP 400 => the server RECOGNIZED this package (and it is consumed)')
print('      HTTP 200 + Organic => NOT recognized (fallback answer)')
print('      HTTP 200 + real token => recognized and fresh (true verdict)')