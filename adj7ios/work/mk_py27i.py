# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = "        t = [AES_SBOX[b] for b in t[1:] + t[:1]]\n"
new = "        t = [bytearray(AES_SBOX)[b] for b in t[1:] + t[:1]]\n"
assert old in s
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched sbox lookup')
