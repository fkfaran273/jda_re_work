# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
lines = io.open(p, encoding='utf-8').read().split('\n')
old0 = 'AES_SBOX = bytes(_affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))'
old1 = '                 if v else _affine(0) for v in range(256))'
assert lines[229] == old0, lines[229]
assert lines[230] == old1, lines[230]
new = [
    'AES_SBOX = bytes(bytearray(',
    '    _affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))',
    '    if v else _affine(0) for v in range(256)))',
]
lines[229:231] = new
io.open(p, 'w', encoding='utf-8').write('\n'.join(lines))
print('patched; AES_SBOX lines now:')
for i in range(229, 233):
    print('  ', lines[i])
