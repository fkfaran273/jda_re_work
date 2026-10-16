# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = '            t = [AES_SBOX[b] for b in t]\n'
new = '            t = [bytearray(AES_SBOX)[b] for b in t]\n'
assert old in s
s = s.replace(old, new)
# any other direct byte-index of the SBOX / tables
s = s.replace('AES_SBOX[b]', 'bytearray(AES_SBOX)[b]')
io.open(p, 'w', encoding='utf-8').write(s)
print('patched sbox index sites:', s.count('bytearray(AES_SBOX)[b]'))
