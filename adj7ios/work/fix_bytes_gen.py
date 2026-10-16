# -*- coding: utf-8 -*-
"""fix_bytes_gen.py -- py2: bytes(<generator>) returns the repr string.
Every such site must become bytes(bytearray(<generator>))."""
import io
import re

p = 'adj7ios_pure_py27.py'
lines = io.open(p, encoding='utf-8').read().split('\n')
out = []
fixed = 0
i = 0
while i < len(lines):
    ln = lines[i]
    # single-line: bytes( X for ... )  / bytes(X for Y)
    m = re.search(r'bytes\(([^()]*\bfor\b[^()]*)\)', ln)
    if m and 'bytearray(' not in m.group(0):
        inner = m.group(1)
        new = 'bytes(bytearray(%s))' % inner
        ln = ln[:m.start()] + new + ln[m.end():]
        fixed += 1
    out.append(ln)
    i += 1
io.open(p, 'w', encoding='utf-8').write('\n'.join(out))
print('single-line fixes:', fixed)
# report any remaining multi-line bytes( ... for ... ) patterns
src = '\n'.join(out)
for mm in re.finditer(r'bytes\((?:[^()]|\n)*?\bfor\b(?:[^()]|\n)*?\)', src):
    seg = mm.group(0)
    if 'bytearray(' not in seg:
        print('REMAINING:', seg[:90].replace('\n', ' '))
