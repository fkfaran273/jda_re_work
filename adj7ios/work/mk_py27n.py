# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = ('        c = spn_chunk(bytes(a ^ b for a, b in zip(record[k:k + 16],'
       ' wa)))\n')
new = ('        c = spn_chunk(bytes(bytearray(a ^ b for a, b in\n'
       '                                     zip(bytearray(record[k:k + 16]),\n'
       '                                         bytearray(wa)))))\n')
assert old in s, 'cbc line not found'
s = s.replace(old, new)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched cbc_encrypt')
