# recog_probe2.py - the VERBATIM blob (byte-exact, header included) with only the
# QUERY/identity varied -> what is the recognition bound to?
# Signal: HTTP 400 ask_in = recognized; 200 + Organic = not recognized.
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_full_chain as F

G = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))
GEN = bytes.fromhex(G['blob_hex'])
Q = {k: v[0] for k, v in urllib.parse.parse_qs(
    urllib.parse.urlsplit(G['query']).query).items()}
print('verbatim blob %d B hdr=%s gps=%s auid=%s'
      % (len(GEN), GEN[:16].hex(), Q['gps_adid'], Q['android_uuid']))
F.USE_DEVICE = True
F.NO_SIGN = False


def q(**over):
    out = dict(Q)
    for k, v in over.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


VARIANTS = [
    ('A verbatim blob + genuine query', GEN, q(), False),
    ('B verbatim blob + pert device_name', GEN, q(device_name='pixel 7'), False),
    ('C verbatim blob + extra param', GEN, q(session_count='7'), False),
    ('D verbatim blob + dropped ui_mode', GEN, q(ui_mode=None), False),
    ('E verbatim blob + fresh android_uuid', GEN,
     q(android_uuid='11111111-2222-3333-4444-555555555555'), False),
    ('F verbatim blob + fresh gps_adid', GEN,
     q(gps_adid='99999999-8888-7777-6666-555555555555'), False),
    ('G verbatim blob + NO Authorization', GEN, q(), True),
]
res = []
for label, blob, params, nosign in VARIANTS:
    F.NO_SIGN = nosign
    code, body = F.send_device('https://app.adjust.com/attribution', params, blob,
                               method='GET')
    short = body.strip().replace('\r\n', '')[:170]
    print('%-36s -> HTTP %s  %s' % (label, code, short), flush=True)
    res.append({'label': label, 'http': code, 'body': short})
    time.sleep(2)
F.NO_SIGN = False
json.dump(res, open(os.path.join(HERE, 'recog_probe2_result.json'), 'w'), indent=1)
print('saved recog_probe2_result.json')