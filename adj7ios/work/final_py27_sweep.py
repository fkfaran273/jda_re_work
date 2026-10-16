# -*- coding: utf-8 -*-
"""final_py27_sweep.py -- make every bytes-iteration in adj7ios_pure_py27.py
yield ints on py2 (bytearray(...) slices), the last py2/py3 difference."""
import io
p = 'adj7ios_pure_py27.py'
s = io.open(p, encoding='utf-8').read()
reps = [
    # spn_chunk: XOR with round keys + S-box lookups
    ('    x = bytes(a ^ b for a, b in zip(P, _RK[0]))\n'
     '    x = bytes(AES_SBOX[v] for v in x)\n',
     '    x = bytes(bytearray(a ^ b for a, b in zip(bytearray(P),\n'
     '                                          bytearray(_RK[0]))))\n'
     '    x = bytes(bytearray(AES_SBOX)[v] for v in bytearray(x))\n'),
    ('        x = bytes(a ^ b for a, b in zip(x, _RK[1 + r]))\n'
     '        x = bytes(AES_SBOX[v] for v in x)\n',
     '        x = bytes(bytearray(a ^ b for a, b in zip(bytearray(x),\n'
     '                                              bytearray(_RK[1 + r]))))\n'
     '        x = bytes(bytearray(AES_SBOX)[v] for v in bytearray(x))\n'),
    ('    return bytes(a ^ b for a, b in zip(x, _RK[14]))\n',
     '    return bytes(bytearray(a ^ b for a, b in zip(bytearray(x),\n'
     '                                               bytearray(_RK[14]))))\n'),
    # _shift_rows / _sr_inverse / _mix_columns / _mix inputs
    ('def _shift_rows(b):\n    out = bytearray(16)\n',
     'def _shift_rows(b):\n    b = bytearray(b)\n    out = bytearray(16)\n'),
    ('def _sr_inverse(b):\n    out = bytearray(16)\n',
     'def _sr_inverse(b):\n    b = bytearray(b)\n    out = bytearray(16)\n'),
    ('def _mix_columns(b):\n    out = bytearray(16)\n',
     'def _mix_columns(b):\n    b = bytearray(b)\n    out = bytearray(16)\n'),
    ('def _mix(b, mat):\n    out = bytearray(16)\n',
     'def _mix(b, mat):\n    b = bytearray(b)\n    out = bytearray(16)\n'),
    # _key_schedule return: bytes(b for ...) over ints is fine
]
n = 0
for a, b in reps:
    if a in s:
        s = s.replace(a, b)
        n += 1
    else:
        print('NOT FOUND:', a.split('\n')[0][:60])
io.open(p, 'w', encoding='utf-8').write(s)
print('replacements applied:', n)
