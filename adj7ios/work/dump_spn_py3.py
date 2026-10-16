# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '.')
import adj7ios_pure as sg3
tests = [bytes(bytearray(range(16))),
         bytes(bytearray([255 - i for i in range(16)])),
         b'\x00' * 16,
         b'\xff' * 16,
         bytes(bytearray([(i * 37 + 11) % 256 for i in range(16)]))]
out = []
for t in tests:
    out.append(sg3.spn_chunk(t).hex().upper())
open('spn_py3.txt', 'w').write('\n'.join(out))
print('py3 spn[0]', out[0])
print('py3 spn[1]', out[1])
