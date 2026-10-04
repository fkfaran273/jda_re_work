"""verify_py27.py -- run under BOTH py2.7 and py3; the hex lines must match.

    py -2.7 verify_py27.py > py27.txt
    python   verify_py27.py > py3.txt
    then diff the two files.

Only rng.getrandbits is used: its sequence is identical on 2.7 and 3.x, so
both runs sign the same inputs.
"""
import hashlib
import random

import adj9_pure_py27 as B

rng = random.Random(20261003)
cert = bytearray.fromhex('fad0f10d60f93c17937b2f1eb6c09691ae7d74bd')
phases = [None, (0x2b,), (0x2b, 0x48)]

for i in range(100):
    sec = rng.getrandbits(31)
    seed = rng.getrandbits(32)
    claims = bytes(bytearray(rng.getrandbits(8)
                             for _ in range(rng.getrandbits(9) % 496 + 4)))
    blob = B.sign(sec, seed, claims, cert, phases[i % 3])
    print('%d %s' % (i, hashlib.sha256(blob).hexdigest()))
