# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
pairs = [
    ('SHA0_HEX = SHA0.hex().upper()',
     'SHA0_HEX = binascii.hexlify(SHA0).upper()'),
    ('% (blob.hex().upper(), ADJ_SIGNING_ID, ALGORITHM, headers_id,',
     '% (_hexup(blob), ADJ_SIGNING_ID, ALGORITHM, headers_id,'),
    ('if blob.hex().upper() != v["sig"]:',
     'if _hexup(blob) != v["sig"]:'),
    ('nonce12 = (int(m.group(1).decode().strip()).to_bytes(8, "little")',
     'nonce12 = struct.pack("<Q", int(m.group(1).decode().strip()))'),
    ('assert commitment_digest(claims, nonce12).hex().upper()',
     'assert _hexup(commitment_digest(claims, nonce12))'),
]
for a, b in pairs:
    if a in s:
        s = s.replace(a, b)
        print('patched:', a[:48])
    else:
        print('NOT FOUND:', a[:48])
io.open(p, 'w', encoding='utf-8').write(s)
print('remaining to_bytes:', s.count('.to_bytes('),
      '| .hex().upper():', s.count('.hex().upper()'))
