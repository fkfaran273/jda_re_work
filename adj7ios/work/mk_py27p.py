# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = '    x = bytes(bytearray(AES_SBOX)[v] for v in bytearray(x))\n'
new = '    x = bytes(bytearray(bytearray(AES_SBOX)[v]\n' \
      '                        for v in bytearray(x)))\n'
n = s.count(old)
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('sbox sites fixed:', n)
