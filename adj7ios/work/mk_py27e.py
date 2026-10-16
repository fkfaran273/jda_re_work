# -*- coding: utf-8 -*-
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
s = s.replace('SEED = bytes.fromhex(\n', 'SEED = binascii.unhexlify(\n')
s = s.replace('DK37 = bytes.fromhex(\n', 'DK37 = binascii.unhexlify(\n')
io.open(p, 'w', encoding='utf-8').write(s)
print('bytes.fromhex left:', s.count('bytes.fromhex'))
