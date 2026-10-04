# mint_exact_send.py - SEND A DEVICE-MINTED BLOB with a query built EXACTLY from the
# map the device signed (mo1.json: blobB64 + auth + mapPairs). Self-contained adb
# sender so the Authorization header is the mint's own. Signal: 400 ask_in = the
# server RECOGNIZED the payload; 200 + Organic = not recognized.
import json
import os
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_full_chain as F

T = os.environ.get('TEMP')
M = json.loads(open(os.path.join(T, 'mo1.json'), 'rb').read().decode('utf-16'))
pairs = M['mapPairs']
auth = M['auth']
print('mint blobB64 %d chars, auth %d chars, stamp %s'
      % (len(M['blobB64']), len(auth), M['stamp']))
HEADER_ONLY = {'adj_signing_id', 'client_sdk', 'headers_id', 'native_version',
               'algorithm', 'adj_verification', 'activity_kind', 'endpoint'}


def q_from(pairs, keep_last=False, exclude=()):
    out = {}
    for k, v in pairs:
        if k in HEADER_ONLY or k in exclude:
            continue
        if not keep_last and k in out:
            continue
        out[k] = v
    return out


def send(params, auth_value):
    parts = ['curl', '-s', '-S', '-k', '--max-time', '45', '-w',
             '\\n###HTTP:%{http_code}', '-H', 'Client-SDK: android5.7.0',
             '-H', 'User-Agent: ' + F.UA, '-H', 'Authorization: ' + auth_value]
    url = 'https://app.adjust.com/attribution'
    parts += [url + '?' + __import__('urllib.parse', fromlist=['x']).urlencode(params)]
    remote = ' '.join(shlex.quote(p) for p in parts)
    p = subprocess.run(['adb', 'shell', remote], capture_output=True, timeout=120)
    out = p.stdout.decode('utf-8', 'replace')
    code = 'ERR'
    if '###HTTP:' in out:
        out, code = out.rsplit('###HTTP:', 1)
        code = code.strip()
    return code, out.strip().replace('\r\n', '')[:170]


CASES = [
    ('M1 exact map (first-wins)', q_from(pairs)),
    ('M2 exact map (last-wins)', q_from(pairs, keep_last=True)),
    ('M3 map minus hardware_name', q_from(pairs, exclude=('hardware_name',))),
]
res = []
for label, q in CASES:
    code, body = send(q, auth)
    tag = 'RECOGNIZED' if code == '400' else (
        'not-recognized' if code == '200' else 'HTTP %s' % code)
    print('%-30s keys=%-2d -> %-14s %s' % (label, len(q), tag, body), flush=True)
    res.append({'label': label, 'keys': len(q), 'http': code, 'tag': tag,
                'body': body})
    time.sleep(2)
json.dump(res, open(os.path.join(HERE, 'mint_exact_send_result.json'), 'w'),
          indent=1)
print('gps in map:', dict(pairs).get('gps_adid'))