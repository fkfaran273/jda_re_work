import verify_hunch_sig as V, re, urllib.parse, struct
import adj7_pure as A
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
head, pt, _ = V.load(30)
f = dict(urllib.parse.parse_qsl(pt, keep_blank_values=True))
sec = V.to_sec(f['sent_at'])
print('sec', sec, f['sent_at'], '| created', f['created_at'])
pat = r'signature="([0-9A-Fa-f]+)"'
m = re.search(pat, head).group(1).upper()
blob = bytes.fromhex(m)
dec = Cipher(algorithms.AES(A.SEED), modes.CBC(blob[:16])).decryptor()
rec = dec.update(blob[16:272]) + dec.finalize()
s = rec.split(b'\x00')[0].decode('latin1')
ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1).strip()
rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
nonce12 = struct.pack('<Q', int(ra)) + bytes.fromhex(rd)
auth2 = A.mint_adj7('click', f, unix_sec=sec, include_block2=True, nonce12=nonce12, campaign=V.CAMP)
w = re.search(pat, auth2).group(1).upper()
print('genu header16', m[:32])
print('mint header16', w[:32])
i = next((i for i, (a, b) in enumerate(zip(m, w)) if a != b), None)
print('first diff at hex', i)
if i is not None:
    print('genu...', m[max(0, i-4):i+12])
    print('mint...', w[max(0, i-4):i+12])
print('sec+1 header test:', A.make_header(sec + 1).hex().upper() == m[:32])
print('sec-1 header test:', A.make_header(sec - 1).hex().upper() == m[:32])
