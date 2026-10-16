# -*- coding: utf-8 -*-
import binascii, sys
sys.path.insert(0, '.')
import adj7ios_pure_py27 as sg2
tests = [bytes(bytearray(range(16))),
         bytes(bytearray([255 - i for i in range(16)])),
         b'\x00' * 16,
         b'\xff' * 16,
         bytes(bytearray([(i * 37 + 11) % 256 for i in range(16)]))]
out = []
for t in tests:
    out.append(binascii.hexlify(sg2.spn_chunk(t)))
open('spn_py2.txt', 'w').write('\n'.join(out))
print('py2 spn[0]', out[0])
print('py2 spn[1]', out[1])
