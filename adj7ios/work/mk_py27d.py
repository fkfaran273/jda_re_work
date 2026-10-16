# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = ('        nonce12 = struct.pack("<Q", int(m.group(1).decode().strip()))\n'
       '                   + bytes.fromhex(m.group(4).decode()))\n')
new = ('        nonce12 = (struct.pack("<Q", int(m.group(1).decode().strip()))\n'
       '                   + binascii.unhexlify(m.group(4).decode()))\n')
if old in s:
    s = s.replace(old, new)
    print('fixed nonce12 join')
s = s.replace('blob = sign(v["second"], bytes.fromhex(v["nonce12"]), claims)',
              'blob = sign(v["second"],\n'
              '                   binascii.unhexlify(v["nonce12"]), claims)')
s = s.replace('assert nonce12 == bytes.fromhex(v["nonce12"])',
              'assert nonce12 == binascii.unhexlify(v["nonce12"])')
io.open(p, 'w', encoding='utf-8').write(s)
print('remaining bytes.fromhex:', s.count('bytes.fromhex'))
