# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = ('def _key_schedule(key):\n'
       '    W = [list(key[i * 4:i * 4 + 4]) for i in range(8)]\n')
new = ('def _key_schedule(key):\n'
       '    kb = bytearray(key)\n'
       '    W = [list(kb[i * 4:i * 4 + 4]) for i in range(8)]\n')
assert old in s
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched key_schedule')
