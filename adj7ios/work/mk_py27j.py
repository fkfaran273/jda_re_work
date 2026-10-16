# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = ('AES_SBOX = bytes(_affine(next(q for q in range(1, 256)'
       ' if _gmul(v, q) == 1))\n'
       '                  if v else _affine(0) for v in range(256))\n')
new = ('AES_SBOX = bytes(bytearray(\n'
       '    _affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))\n'
       '    if v else _affine(0) for v in range(256)))\n')
assert old in s, 'sbox block not found'
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched AES_SBOX')
