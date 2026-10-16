# -*- coding: utf-8 -*-
import binascii, sys
sys.path.insert(0, '.')
import adj7ios_pure_py27 as sg

P1 = bytes(bytearray(range(16)))
P2 = bytes(bytearray([255 - i for i in range(16)]))
print('RK0', binascii.hexlify(sg._RK[0]), 'len', len(sg._RK[0]))
print('RK14', binascii.hexlify(sg._RK[14])[:32])
print('SBOX len', len(sg.AES_SBOX), 'SBOX[0:4]', repr(sg.AES_SBOX[:4]))

def steps(P):
    x = bytes(bytearray(a ^ b for a, b in zip(bytearray(P),
                                              bytearray(sg._RK[0]))))
    print('  after rk0 xor:', binascii.hexlify(x)[:32])
    x = bytes(bytearray(sg.AES_SBOX)[v] for v in bytearray(x))
    print('  after sbox   :', binascii.hexlify(x)[:32])
    x = sg._shift_rows(x)
    print('  after srow   :', binascii.hexlify(x)[:32])
    x = sg._mix_columns(x)
    print('  after mix    :', binascii.hexlify(x)[:32])
    return x

print('P1'); steps(P1)
print('P2'); steps(P2)
