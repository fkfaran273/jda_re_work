"""make_py27_adj7.py — regenerate adj7_pure_py27.py from adj7_pure.py.

Transforms: bytes(generator) -> py2-safe shims, int.to_bytes/from_bytes ->
struct, .hex()/bytes.fromhex -> binascii shims.

    python make_py27_adj7.py && py -2.7 adj7_pure_py27.py --selftest
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "adj7_pure.py"), encoding="utf-8").read()

SHIMS = '''
import binascii

def _hex(b):
    return binascii.hexlify(b)

def _fh(s):
    return binascii.unhexlify(s)

def _x2(a, b):
    return bytearray(x ^ y for x, y in zip(bytearray(a), bytearray(b)))

def _sb(x):
    return bytearray(AES_SBOX[v] for v in bytearray(x))

def _i2b(v):
    return struct.pack(">I", v)

'''

R = [
    # shims injected after the stdlib imports
    ('import time\n',
     'import time\n' + SHIMS),
    # constants
    ('SEED = bytes.fromhex(', 'SEED = _fh('),
    ('DK37 = bytes.fromhex(', 'DK37 = _fh('),
    ('SHA0_HEX = SHA0.hex().upper()', 'SHA0_HEX = _hex(SHA0).upper()'),
    # SBOX construction (bytes(generator) is broken on py2; keep as bytearray
    # so AES_SBOX[b] indexes to int)
    ('AES_SBOX = bytes(_affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))\n'
     '                 if v else _affine(0) for v in range(256))',
     'AES_SBOX = bytearray([_affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))\n'
     '                      if v else _affine(0) for v in range(256)])'),
    # key schedule inner join
    ('return [bytes(b for w in W[4 * r:4 * r + 4] for b in w) for r in range(15)]',
     'return [bytes(bytearray([b for w in W[4 * r:4 * r + 4] for b in w]))\n'
     '            for r in range(15)]'),
    # W words must be int lists even though SEED is a py2 str
    ('W = [list(key[i * 4:i * 4 + 4]) for i in range(8)]',
     'W = [list(bytearray(key[i * 4:i * 4 + 4])) for i in range(8)]'),
    # shift/mix return bytearray so slicing keeps ints on py2
    ('''    out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytes(out)''',
     '''    out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytearray(out)'''),
    ('''            out[4 * q + i] = v
    return bytes(out)''',
     '''            out[4 * q + i] = v
    return bytearray(out)'''),
    # header
    ('return b"".join(v.to_bytes(4, "big") for v in w)',
     'return b"".join(_i2b(v) for v in w)'),
    # commitment / record
    ('A = str(int.from_bytes(nonce12[0:8], "little")).rjust(20)',
     'A = str(struct.unpack("<Q", nonce12[0:8])[0]).rjust(20)'),
    ("d8 = nonce12[8:12].hex().upper()",
     "d8 = _hex(nonce12[8:12]).upper()"),
    ("H.hex().upper().encode()",
     "_hex(H).upper().encode()"),
    # spn/cbc xor helpers
    ("x = bytes(a ^ b for a, b in zip(P, keys[0]))",
     "x = _x2(P, keys[0])"),
    ("x = bytes(AES_SBOX[v] for v in x)\n    for r in range(13):",
     "x = _sb(x)\n    for r in range(13):"),
    ("x = bytes(a ^ b for a, b in zip(x, keys[1 + r]))",
     "x = _x2(x, keys[1 + r])"),
    ("x = bytes(AES_SBOX[v] for v in x)\n    x = _shift_rows(x)",
     "x = _sb(x)\n    x = _shift_rows(x)"),
    ("return bytes(a ^ b for a, b in zip(x, keys[14]))",
     "return _x2(x, keys[14])"),
    ("c = spn_chunk(bytes(a ^ b for a, b in zip(record[k:k + 16], wa)),\n                      keys)",
     "c = spn_chunk(_x2(record[k:k + 16], wa), keys)"),
    # cbc accumulates as bytearray on py2
    ("out, wa = b\"\", header", "out, wa = bytearray(), header"),
    ("        out += c\n        wa = c\n    return out",
     "        out += c\n        wa = c\n    return bytes(out)"),
    # cert slot: direct upper-hex, no fromhex round-trip
    ("cert40 = cert_sha1.upper().encode() if cert_sha1 else None",
     "cert40 = cert_sha1.upper().encode() if cert_sha1 else None"),
    # auth hex
    ('% (blob.hex().upper(), adj_signing_id, ALGORITHM, headers_id,',
     '% (_hex(blob).upper(), adj_signing_id, ALGORITHM, headers_id,'),
]
for old, new in R:
    assert old in src, "pattern missing: %r" % old[:60]
    src = src.replace(old, new, 1)

# remaining bytes.fromhex occurrences (frozen vectors etc.)
src = src.replace('bytes.fromhex(', '_fh(')

out = os.path.join(HERE, "adj7_pure_py27.py")
cookie = "# " + "-*- coding: utf-8 -*-" + chr(10)
open(out, "w", encoding="utf-8").write(cookie + src)
print("wrote", out)
