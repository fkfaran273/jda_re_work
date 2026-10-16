# -*- coding: utf-8 -*-
"""fix_advance_model.py -- clear three-way advance semantics + stateless selftest.

    advance=None  -> device behaviour: one MINSTD stream per signing second,
                     advanced on every further sign in that second
    advance=0     -> stateless: make_header(second) (the classic law)
    advance=N     -> stateless: skip N further blocks (mint a known blob)
The selftest mints each vector independently, so it must use advance=0.
"""
import io

for p, is27 in (('adj7ios_pure.py', False), ('adj7ios_pure_py27.py', True)):
    s = io.open(p, encoding='utf-8').read()
    old = '''    if not advance:          # None or 0 -> device behaviour (stream state)
        x = _STREAM.get(sec)
        if x is None:
            x = sec % _M31 or 1
        header, x = _stream_block(x)
        _STREAM[sec] = x
    else:
        x = sec % _M31 or 1
        header = None
        for _ in range(int(advance) + 1):
            header, x = _stream_block(x)
'''
    new = '''    if advance is None:      # device behaviour (stream state)
        x = _STREAM.get(sec)
        if x is None:
            x = sec % _M31 or 1
        header, x = _stream_block(x)
        _STREAM[sec] = x
    else:                    # stateless: 0 = first block, N = N blocks ahead
        x = sec % _M31 or 1
        header = None
        for _ in range(int(advance) + 1):
            header, x = _stream_block(x)
'''
    if old in s:
        s = s.replace(old, new)
        print(p, 'sign() advance model patched')
    else:
        print(p, 'sign() block NOT FOUND (inspect)')
    # selftest: stateless per-vector mint
    if is27:
        o = ('    blob = sign(v["second"],\n'
             '                   binascii.unhexlify(v["nonce12"]), claims)\n')
        n = ('    blob = sign(v["second"],\n'
             '                   binascii.unhexlify(v["nonce12"]), claims,\n'
             '                   advance=0)\n')
    else:
        o = '    blob = sign(v["second"], bytes.fromhex(v["nonce12"]), claims)\n'
        n = ('    blob = sign(v["second"], bytes.fromhex(v["nonce12"]),'
             ' claims,\n'
             '                   advance=0)\n')
    if o in s:
        s = s.replace(o, n)
        print(p, 'selftest patched to advance=0')
    else:
        print(p, 'selftest call NOT FOUND')
    io.open(p, 'w', encoding='utf-8').write(s)
