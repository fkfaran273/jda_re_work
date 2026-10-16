import os, re, sys, urllib.parse, hashlib, hmac, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg
sys.path.insert(0, r'C:\Users\Apps\Download\com.penti.app\adj7') if False else None
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

RAW = os.path.join(HERE, 'saz_berain', 'raw')
t = open(os.path.join(RAW, '045_c.txt'), encoding='utf-8', errors='replace', newline='').read()
head, _, body = t.partition('\r\n\r\n')
auth = [l.split(': ', 1)[1] for l in head.split('\r\n') if l.startswith('Authorization')][0]
sig = re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1).upper()
blob = bytes.fromhex(sig)
hdr, enc, tag = blob[:16], blob[16:272], blob[272:]
print('tag HMAC(DK37) ok:', hmac.new(sg.DK37, enc, hashlib.sha256).digest() == tag)
dec = Cipher(algorithms.AES(sg.SEED), modes.CBC(hdr)).decryptor()
rec = dec.update(enc) + dec.finalize()
s = rec.split(b'\x00')[0].decode('latin1')
ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1)
rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
nonce12 = struct.pack('<Q', int(ra.strip())) + bytes.fromhex(rd)
print('nonce12:', nonce12.hex())
print('record a (u64le nonce):', ra.strip()[:24], '| d:', rd)
cands = {
  'sha256(nonce12)[:16]': hashlib.sha256(nonce12).digest()[:16],
  'sha256(record)[:16]': hashlib.sha256(rec).digest()[:16],
  'sha256(body)[:16]': hashlib.sha256(enc).digest()[:16],
  'nonce12 + sha0[:4]': nonce12 + hashlib.sha256(b'').digest()[:4],
}
for k, v in cands.items():
    print('   %-22s %s' % (k, v.hex().upper() == hdr.hex().upper()))
print('target:', hdr.hex().upper())
# also try Android bionic law
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
try:
    import adj7_pure as AP
    hit = None
    sent = dict(urllib.parse.parse_qsl(body.strip(), keep_blank_values=True))['sent_at']
    from datetime import datetime, timezone
    m = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z([+-]\d\d)(\d\d)', sent)
    base = int(datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp() - int(m.group(2))*3600 - int(m.group(3))*60)
    for d in range(-7200, 7201):
        if AP.make_header(base + d).hex().upper() == hdr.hex().upper():
            hit = d; break
    print('android-bionic header delta:', hit)
except Exception as e:
    print('android law err', e)
