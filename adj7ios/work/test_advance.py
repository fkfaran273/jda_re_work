import os, re, sys, urllib.parse, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

t = open(os.path.join(HERE, 'saz_berain', 'raw', '045_c.txt'),
         encoding='utf-8', errors='replace', newline='').read()
a = re.search('signature="([0-9A-Fa-f]+)"', t).group(1).upper()
params = dict(urllib.parse.parse_qsl(t.partition('\r\n\r\n')[2].strip(),
                                     keep_blank_values=True))
blob = bytes.fromhex(a)
dec = Cipher(algorithms.AES(sg.SEED), modes.CBC(blob[:16])).decryptor()
rec = dec.update(blob[16:272]) + dec.finalize()
s = rec.split(b'\x00')[0].decode('latin1')
ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1)
rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
nonce12 = struct.pack('<Q', int(ra.strip())) + bytes.fromhex(rd)
SEC = 1779250802
for adv in (0, 1):
    auth, b2 = sg.sign_request(params, 'click', second=SEC, nonce12=nonce12,
                               client_sdk='ios5.5.2', headers_id='8',
                               native_version='3.62.0', advance=adv)
    print('advance=%d WHOLE=%s' % (adv, b2.hex().upper() == a))
