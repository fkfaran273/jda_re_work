# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = ('    return [bytes(b for w in W[4 * r:4 * r + 4] for b in w)\n'
       '            for r in range(15)]\n')
new = ('    return [bytes(bytearray(b for w in W[4 * r:4 * r + 4] for b in w))\n'
       '            for r in range(15)]\n')
assert old in s, 'key_schedule return not found'
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched _key_schedule return')
