# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
n = s.count("rb'") + s.count('rb"')
s = s.replace("rb'", "b'").replace('rb"', 'b"')
io.open(p, 'w', encoding='utf-8').write(s)
print('rb-literals converted:', n)
