# -*- coding: utf-8 -*-
"""fix_verify_py27.py -- py2-safe inverse SPN (byte indexing)."""
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
old = '''    def spn_inv(C):
        y = _sr_inverse(bytes(a ^ b for a, b in zip(C, _RK[14])))
        for r in range(13, 0, -1):
            c = bytes(bytearray(INVBOX[v] for v in y))
            b = bytes(a ^ b for a, b in zip(c, _RK[r]))
            a = _mix(b, ICM)
            y = _sr_inverse(a)
        p = bytes(bytearray(INVBOX[v] for v in y))
        return bytes(a ^ b for a, b in zip(p, _RK[0]))
'''
new = '''    INV = bytearray(INVBOX)

    def spn_inv(C):
        y = _sr_inverse(bytes(bytearray(a ^ b for a, b in
                                       zip(bytearray(C),
                                           bytearray(_RK[14])))))
        for r in range(13, 0, -1):
            c = bytes(bytearray(INV[v] for v in bytearray(y)))
            b = bytes(bytearray(a ^ b for a, b in zip(bytearray(c),
                                                      bytearray(_RK[r]))))
            a = _mix(b, ICM)
            y = _sr_inverse(a)
        p = bytes(bytearray(INV[v] for v in bytearray(y)))
        return bytes(bytearray(a ^ b for a, b in zip(bytearray(p),
                                                     bytearray(_RK[0]))))
'''
assert old in s, 'spn_inv block not found'
s = s.replace(old, new)
old2 = ('        out += bytes(a ^ b for a, b in zip(spn_inv(blk), prev))\n')
new2 = ('        out += bytes(bytearray(a ^ b for a, b in\n'
        '                                zip(bytearray(spn_inv(blk)),\n'
        '                                    bytearray(prev))))\n')
assert old2 in s
s = s.replace(old2, new2)
io.open(p, 'w', encoding='utf-8').write(s)
print('patched inverse SPN')
