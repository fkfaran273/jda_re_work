import os, sys, re, urllib.parse
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7_pure as A
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
CAMP = {"package_name":"social.hunch.app","app_version":"3.2.33","app_token":"vf3lochhmgw0","client_sdk":"flutter5.5.0@android5.5.0","cert_sha1":"aa92a18790f85d4e9b5199c7792c55f2fb0f61e1","adj_signing_id":"1300000","algorithm":"adj7","headers_id":"8","native_version":"3.62.0"}
def load(n):
    t = open(os.path.join(HERE,'saz_hunch_new','raw','%02d_c.txt'%n), encoding='utf-8', errors='replace', newline='').read()
    head, _, body = t.partition('\r\n\r\n')
    line0 = t.split('\r\n',1)[0]
    if line0.startswith('GET') and '?' in line0:
        qs = line0.split(' ',2)[1].split('?',1)[1].rsplit(' ',1)[0]
        return head, qs.strip(), True
    return head, body.strip(), False
from datetime import datetime, timezone
def to_sec(s):
    m = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z([+-]\d\d)(\d\d)', s)
    return int(datetime.strptime(m.group(1),'%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp() - int(m.group(3))*3600 - int(m.group(4))*60)
for n, kind in [(29,'session'),(30,'click'),(32,'attribution')]:
    head, params_text, is_q = load(n)
    f = dict(urllib.parse.parse_qsl(params_text, keep_blank_values=True))
    sec = to_sec(f['sent_at'])
    m = re.search(r'signature="([0-9A-Fa-f]+)"', head)
    blob = bytes.fromhex(m.group(1))
    tagok = A.verify_tag(blob)
    dec = Cipher(algorithms.AES(A.SEED), modes.CBC(blob[:16])).decryptor()
    rec = dec.update(blob[16:272]) + dec.finalize()
    s = rec.split(b'\x00')[0].decode('latin1')
    rh = re.search(r'"b":\s*"([0-9A-Fa-f]+)"', s).group(1).upper()
    rc = re.search(r'"c":\s*"([0-9A-Fa-f]+)"', s).group(1).upper()
    ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1).strip()
    rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
    import struct
    nonce12 = struct.pack('<Q', int(ra)) + bytes.fromhex(rd)
    claims = A.build_claims(kind, dict(f, activity_kind=kind, client_sdk=CAMP['client_sdk']), include_block2=True)
    h = A.commitment_digest(claims, nonce12, rc.encode()).hex().upper()
    auth2 = A.mint_adj7(kind, f, unix_sec=sec, include_block2=True, nonce12=nonce12, campaign=CAMP)
    wire = re.search(r'signature="([0-9A-Fa-f]+)"', auth2).group(1).upper()
    print('row %d %-11s tag=%s cert=%s Hmatch=%s WHOLE=%s claims=%dB' % (n, kind, tagok, rc==CAMP['cert_sha1'].upper(), h==rh, wire==m.group(1).upper(), len(claims)))
