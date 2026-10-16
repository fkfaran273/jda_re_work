import os, re, struct, sys, urllib.parse
from datetime import datetime, timezone
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

RAW = os.path.join(HERE, 'saz_berain', 'raw')
SDK = 'ios5.5.2'

t = open(os.path.join(RAW, '045_c.txt'), encoding='utf-8', errors='replace', newline='').read()
head, _, body = t.partition('\r\n\r\n')
auth = [l.split(': ', 1)[1] for l in head.split('\r\n') if l.startswith('Authorization')][0]
sig = re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1).upper()
params = dict(urllib.parse.parse_qsl(body.strip(), keep_blank_values=True))
print('params (%d):' % len(params))
for k, v in sorted(params.items()):
    print('   %-26s %s' % (k, v[:70]))
blob = bytes.fromhex(sig)
dec = Cipher(algorithms.AES(sg.SEED), modes.CBC(blob[:16])).decryptor()
rec = dec.update(blob[16:272]) + dec.finalize()
s = rec.split(b'\x00')[0].decode('latin1')
print('record:', s[:200])
ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1)
rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
nonce12 = struct.pack('<Q', int(ra.strip())) + bytes.fromhex(rd)
hdr = blob[:16]
print('genuine header16:', hdr.hex())
sent = params['sent_at']
m = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z([+-]\d\d)(\d\d)', sent)
base = int(datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp() - int(m.group(2))*3600 - int(m.group(3))*60)
for d in range(-300, 301):
    if sg.make_header(base + d).hex().upper() == hdr.hex().upper():
        print('header matches at delta', d); break
else:
    print('header: NO delta in +-300')
# claims: recompute H with each candidate kind and compare to record b
rh = re.search(r'"b":\s*"([0-9A-Fa-f]+)"', s).group(1).upper()
rc = re.search(r'"c":\s*"([0-9A-Fa-f]+)"', s).group(1).upper()
for kind in ('click', 'sdk_click', 'event', 'session'):
    a2, b2 = sg.sign_request(params, kind, second=base, nonce12=nonce12, client_sdk=SDK, headers_id='8', native_version='3.62.0')
    print('kind=%-11s H_match=%s WHOLE=%s' % (kind, sg.commitment_digest(sg.build_claims(kind, params, client_sdk=SDK, include_block2=True), nonce12, bytes.fromhex(rc)).hex().upper() == rh, b2.hex().upper() == sig))
