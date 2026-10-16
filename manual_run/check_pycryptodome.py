"""check_pycryptodome.py -- can the whitening cipher be handed to pycryptodome?

The cipher is AES-256-shaped: CBC from the header, standard S-box/ShiftRows/
MixColumns, 15 round keys.  The EFFECTIVE round keys are KB_r ^ 0x55 (the
AddRoundKey XORs 0x55 and T = AES_SBOX ^ 0x55 cancels the same way in
SubBytes, so only the key bytes carry the mask).  pycryptodome only accepts
a 32-byte master and runs the STANDARD AES-256 expansion -- so drop-in works
iff (KB_r ^ 0x55) == AES256_Expand(KB[0:32] ^ 0x55) for all 15 rounds.

The old gate (verify_aes256_claim) tested KB without the mask -- the masked
variant has never been checked.  This settles it.
"""
import time
import random

import adj9_pure as P
from verify_aes256_claim import aes256_expand

MASK = bytes([0x55]) * 16

# the effective schedule, as the round loop actually uses it
eff = [bytes(a ^ 0x55 for a in P.KB[16 * r:16 * r + 16]) for r in range(15)]

print('== is the effective schedule (KB_r ^ 0x55) a standard expansion? ==')
for label, master in [('KB[0:32] ^ 0x55', bytes(a ^ 0x55 for a in P.KB[0:32])),
                      ('KB[0:32] as-is ', P.KB[0:32])]:
    rk = aes256_expand(master)
    same = [bytes(rk[i]) == eff[i] for i in range(15)]
    print('  master %-16s -> %d/15 round keys match (first mismatch: round %d)'
          % (label, sum(same),
             next((i for i, s in enumerate(same) if not s), None)))

# if the masked master works, pycryptodome must reproduce encrypt() exactly
if bytes(a ^ 0x55 for a in P.KB[0:32]) and sum(
        bytes(aes256_expand(bytes(a ^ 0x55 for a in P.KB[0:32]))[i]) == eff[i]
        for i in range(15)) == 15:
    from Crypto.Cipher import AES
    master = bytes(a ^ 0x55 for a in P.KB[0:32])
    rng = random.Random(42)
    ok = True
    for _ in range(300):
        rec = bytes(rng.getrandbits(8) for _ in range(144))
        hdr = bytes(rng.getrandbits(8) for _ in range(16))
        theirs = AES.new(master, AES.MODE_CBC, hdr).encrypt(rec)
        if theirs != P.encrypt(rec, hdr):
            ok = False
            break
    print('== pycryptodome AES-256-CBC vs our encrypt(): %s =='
          % ('300/300 BYTE-EXACT' if ok else 'MISMATCH'))

    # speed: pure python vs pycryptodome, 2000 full records
    rec = bytes(range(144))
    hdr = P.make_header(1790341508)
    t0 = time.perf_counter()
    for _ in range(2000):
        P.encrypt(rec, hdr)
    t_pure = time.perf_counter() - t0
    c = AES.new(master, AES.MODE_CBC, hdr)
    t0 = time.perf_counter()
    for _ in range(2000):
        AES.new(master, AES.MODE_CBC, hdr).encrypt(rec)
    t_crypto = time.perf_counter() - t0
    print('   pure python : %5.0f ms / 2000 records (%.1f ms each)'
          % (t_pure * 1000, t_pure / 2))
    print('   pycryptodome: %5.0f ms / 2000 records (%.3f ms each)'
          % (t_crypto * 1000, t_crypto / 2))
    print('   speedup     : %.0fx' % (t_pure / t_crypto))
else:
    print('== NO: the schedule is custom; pycryptodome cannot express it ==')
    print('   (the native .so uses ARM AESE/AESMC instructions, which take')
    print('    per-round key bytes from registers -- arbitrary schedules are')
    print('    trivial in hardware and impossible through a master-key API)')
