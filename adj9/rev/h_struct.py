# h_struct.py - is #4 ("H", 32 B) random or a bit-packed record? Compare byte/bit
# statistics of the 3 live H values against the #0 tiles (control for uniform).
import json
import os
import struct
import sys

REV = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REV)

# reuse the segmentation without re-printing: read det3/rand_hunt data instead
D = json.load(open(os.path.join(REV, 'det3_result.json'), encoding='utf-8'))
print('det3_result entries:', len(D), 'keys:', list(D[0].keys()))

# the three live H values + tiles come from rand_hunt.log / vd014.log; hardcode
# them here from the trace (verified by rand_hunt.py + verify_d014.py):
H_HEX = [
    '00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e',
    '04000500800084409540410065400448714af5c887c875e8a2906389b08e8c8b',
    '0010008000b000a82098003c08000a9820958aa10a3e04b0205f123f5e3c5feb',
]
TILE_HEX = [
    'db50f44cb63798ccdab7f51ab7d0992b',
    '2ec65f51efdf3cd88c5688294d4f9e48',
    '011d4d1e13227bce21426d41337d5f21',
]
Hs = [bytes.fromhex(x) for x in H_HEX]
Ts = [bytes.fromhex(x) for x in TILE_HEX]


def stats(name, bufs):
    allb = b''.join(bufs)
    n = len(allb)
    z = allb.count(0)
    lo = sum(1 for b in allb if b < 0x10)
    hi = sum(1 for b in allb if b >= 0x80)
    print('%-8s n=%d  zeros=%d (%.1f%%)  <0x10=%d (%.1f%%)  >=0x80=%d (%.1f%%)'
          % (name, n, z, 100.0 * z / n, lo, 100.0 * lo / n, hi, 100.0 * hi / n))
    hist = [round(100.0 * sum(1 for b in allb if (b >> 4) == h) / n) for h in range(16)]
    print('         high-nibble hist (0..F): %s' % hist)


print()
print('=== byte statistics (uniform random: 6.25%% per high nibble) ===')
stats('H #4', Hs)
stats('tile', Ts)

print()
print('=== per-bit-position constancy across the 3 live H values ===')
cons0 = cons1 = var = 0
bit0, bit1 = [], []
for byte_i in range(32):
    for bit in range(8):
        vals = [(h[byte_i] >> bit) & 1 for h in Hs]
        if all(v == 0 for v in vals):
            cons0 += 1
            bit0.append((byte_i, bit))
        elif all(v == 1 for v in vals):
            cons1 += 1
            bit1.append((byte_i, bit))
        else:
            var += 1
print('  always-0: %d  always-1: %d  varying: %d  (of 256 bits)'
      % (cons0, cons1, var))
print('  always-0 (byte,bit): %s' % bit0[:24])
print('  always-1 (byte,bit): %s' % bit1[:24])

print()
print('=== 16-bit word views ===')
for i, h in enumerate(Hs):
    le = [struct.unpack('<H', h[k:k + 2])[0] for k in range(0, 32, 2)]
    be = [struct.unpack('>H', h[k:k + 2])[0] for k in range(0, 32, 2)]
    print('  H%d LE16: %s' % (i, ' '.join('%04x' % p for p in le)))
    print('     BE16: %s' % ' '.join('%04x' % p for p in be))
    print('     16-bit range: max=%04x  #<0x400=%d/16'
          % (max(le), sum(1 for p in le if p < 0x400)))
print()
print('=== compare with the constant #8 (bffffffffffffd1f0007000000000000) ===')
c8 = bytes.fromhex('bffffffffffffd1f0007000000000000')
for i, h in enumerate(Hs):
    xor = bytes(a ^ b for a, b in zip(h[:16], c8))
    print('  H%d[0:16] ^ #8 = %s' % (i, xor.hex()))
    xor2 = bytes(a ^ b for a, b in zip(h[16:32], c8))
    print('  H%d[16:32] ^ #8 = %s' % (i, xor2.hex()))