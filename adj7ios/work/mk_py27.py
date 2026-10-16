# -*- coding: utf-8 -*-
"""mk_py27.py -- generate adj7ios_pure_py27.py from adj7ios_pure.py."""
import io

src = io.open('adj7ios_pure.py', encoding='utf-8').read()
out = src
out = out.replace('import base64, binascii, hashlib, hmac, os, struct, time',
                  'import binascii, hashlib, hmac, os, struct, time')
out = out.replace('nonce12[8:12].hex().upper()', '_hexup(nonce12[8:12])')
out = out.replace('H.hex().upper()', '_hexup(H)')
out = out.replace('bytes.fromhex("', 'binascii.unhexlify("')
out = out.replace('int.from_bytes(nonce12[0:8], "little")',
                  'struct.unpack("<Q", nonce12[0:8])[0]')
out = out.replace('v.to_bytes(4, "big")', 'struct.pack(">I", v)')
out = out.replace('"".join(parts).encode("latin1")',
                  '_latin1("".join(parts))')

helper = '''

def _hexup(b):
    """binascii.hexlify works on both; .hex() does not exist on py2."""
    return binascii.hexlify(bytes(bytearray(b))).upper()


def _latin1(s):
    """str -> bytes in latin-1 on BOTH pythons."""
    return bytes(bytearray(s, "latin1"))
'''
anchor = 'SHA0 = hashlib.sha256(b"").digest()'
assert anchor in out
out = out.replace(anchor, helper.strip() + '\n\n\n' + anchor, 1)
io.open('adj7ios_pure_py27.py', 'w', encoding='utf-8').write(out)
print('written lines:', out.count('\n'))
print('to_bytes left:', out.count('.to_bytes('),
      '| from_bytes left:', out.count('int.from_bytes'),
      '| .hex() left:', out.count('.hex().upper()'))
