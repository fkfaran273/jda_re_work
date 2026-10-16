# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = ('INVBOX = [0] * 256\n'
       'for _i, _v in enumerate(AES_SBOX):\n'
       '    INVBOX[_v] = _i\n')
new = ('INVBOX = [0] * 256\n'
       'for _i, _v in enumerate(bytearray(AES_SBOX)):\n'
       '    INVBOX[_v] = _i\n')
assert old in s
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched INVBOX')
