# h_ten.py - quantify #4 (H) structure across ALL 10 harvested samples and test
# bit-order hypotheses (sparse head + dense tail = bit-packed record).
import json
import os
import struct

REV = os.path.dirname(os.path.abspath(__file__))
S = json.load(open(os.path.join(REV, 'h_samples.json'), encoding='utf-8'))
Hs = [bytes.fromhex(h) for h in S]
print('H samples: %d' % len(Hs))

PW2 = {1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80}


def report(name, bufs):
    allb = b''.join(bufs)
    n = len(allb)
    z = allb.count(0)
    lo = sum(1 for b in allb if b < 0x10)
    pw = sum(1 for b in allb if b in PW2)
    print('%-16s zeros %4.1f%%  <0x10 %4.1f%%  power-of-2 %4.1f%%'
          % (name, 100.0 * z / n, 100.0 * lo / n, 100.0 * pw / n))


print()
print('=== baseline (uniform random: zeros 0.4%%, <0x10 6.2%%, pow2 3.1%%) ===')
report('H as-is', Hs)
report('per-byte BITREV', [bytes(int(format(b, "08b")[::-1], 2) for b in h) for h in Hs])
report('LE32 view', [b''.join(h[i:i + 4][::-1] for i in range(0, 32, 4)) for h in Hs])
report('LE16 view', [b''.join(h[i:i + 2][::-1] for i in range(0, 32, 2)) for h in Hs])
report('whole 256b rev', [bytes(int(format(int.from_bytes(h, 'big'), '0256b')[::-1], 2)
                                .to_bytes(32, 'big')) for h in Hs])

print()
print('=== per-byte-position: zeros / distinct values across %d samples ===' % len(Hs))
print('byte : zeros  distinct  sample values')
for i in range(32):
    col = [h[i] for h in Hs]
    print('  %2d :  %2d/%d     %2d      %s'
          % (i, col.count(0), len(Hs), len(set(col)),
             ' '.join('%02x' % v for v in col)))

print()
print('=== always-0 / always-1 bits across all %d samples ===' % len(Hs))
c0 = c1 = var = 0
head0 = []
for i in range(32):
    for bit in range(8):
        vals = [(h[i] >> bit) & 1 for h in Hs]
        if not any(vals):
            c0 += 1
            head0.append((i, bit))
        elif all(vals):
            c1 += 1
        else:
            var += 1
print('  always-0: %d  always-1: %d  varying: %d  (of 256)'
      % (c0, c1, var))
print('  chance for uniform: always-0 %.1f, always-1 %.1f'
      % (256 * 0.5 ** len(Hs), 256 * 0.5 ** len(Hs)))
print('  always-0 bit map (byte:bits):')
by_byte = {}
for i, b in head0:
    by_byte.setdefault(i, []).append(b)
for i in sorted(by_byte):
    print('    byte %2d: bits %s' % (i, by_byte[i]))

print()
print('=== leading-zero-bit run length per sample (varint/bitstream smell) ===')
for k, h in enumerate(Hs):
    v = int.from_bytes(h, 'big')
    print('  H%-2d leading zero bits: %2d of 256' % (k, 256 - v.bit_length()))