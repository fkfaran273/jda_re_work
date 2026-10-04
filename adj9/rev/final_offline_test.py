# final_offline_test.py - THE DECISIVE TEST: does the server recognize a blob WE
# signed, provided the query's claim set EXACTLY equals the signed payload?
#   V1 consistent   (query keys == signed claim keys)  -> expect 400 ask_in if the
#                                                          payload-match model holds
#   V2 query missing hardware_name                     -> expect 200 Organic
#   V3 query with an extra claim (session_length)      -> expect 200 Organic
#   V4 verbatim genuine blob + genuine query (control) -> 400
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_full_chain as F
import adj9_forge as FG

GPS = '0e789180-17da-440b-b1c3-0349d40e0e93'      # record exists -> 400 signal
W = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
si = W['sign_inputs'][W['golden_sign_input_idx']]
val = {}
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        val[k] = v
val['gps_adid'] = GPS
print('claim map (%d keys): %s' % (len(val), sorted(val)))
BLOCK2 = {'activity_kind', 'client_sdk', 'headers_id', 'native_version',
          'adj_signing_id'}
claims = [k for k in val if k not in BLOCK2]
print('query claim keys (%d): %s' % (len(claims), claims))

second = int(time.time())
status, blob, h = FG.make_signature_map(val, 'session', second=second)
print('maker: status=%s blob=%d B hdr=%s' % (status, len(blob), blob[:16].hex()))
auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
        % __import__('base64').b64encode(blob).decode())

G = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))
GEN = bytes.fromhex(G['blob_hex'])
GQ = {k: v[0] for k, v in urllib.parse.parse_qs(
    urllib.parse.urlsplit(G['query']).query).items()}

F.USE_DEVICE = True
F.NO_SIGN = False
F._auth_header = lambda b: auth          # use OUR header verbatim


def run(label, params, b, expect):
    code, body = F.send_device('https://app.adjust.com/attribution', params, b,
                               method='GET')
    short = body.strip().replace('\r\n', '')[:150]
    tag = 'RECOGNIZED' if code == 400 else ('not-recognized' if code == 200
                                            else 'HTTP %s' % code)
    print('%-42s -> %-14s %s' % (label, tag, short), flush=True)
    return {'label': label, 'http': code, 'tag': tag, 'expect': expect}


res = []
V1 = {k: val[k] for k in claims}
res.append(run('V1 consistent (crafted blob)', V1, blob, '400'))
V2 = dict(V1)
V2.pop('hardware_name', None)
res.append(run('V2 query missing hardware_name', V2, blob, '200'))
V3 = dict(V1)
V3['session_length'] = '42'
res.append(run('V3 query extra session_length', V3, blob, '200'))
res.append(run('V4 verbatim genuine (control)', GQ, GEN, '400'))
json.dump({'claims': claims, 'status': status, 'runs': res},
          open(os.path.join(HERE, 'final_offline_test_result.json'), 'w'), indent=1)
print('saved final_offline_test_result.json')