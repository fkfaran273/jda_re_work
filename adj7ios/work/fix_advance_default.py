# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure.py'
s = io.open(p, encoding='utf-8').read()
old = '''    sec = int(second)
    if advance is None:
'''
new = '''    sec = int(second)
    if not advance:          # None or 0 -> device behaviour (stream state)
'''
assert old in s
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched py3 sign()')

p2 = 'adj7ios_pure_py27.py'
s2 = io.open(p2, encoding='utf-8').read()
old2 = '''    sec = int(second)
    if advance is None:
'''
new2 = '''    sec = int(second)
    if not advance:          # None or 0 -> device behaviour (stream state)
'''
if old2 in s2:
    s2 = s2.replace(old2, new2)
    io.open(p2, 'w', encoding='utf-8').write(s2)
    print('patched py27 sign()')
else:
    print('py27 sign() block differs -- inspect')
