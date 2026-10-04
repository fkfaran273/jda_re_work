# h_map.py - per-byte alphabet of #4 (H) across the 3 live signings: a small
# alphabet per byte = a bit-packed/structured record; uniform = a MAC/hash.
import struct

H_HEX = [
    '00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e',
    '04000500800084409540410065400448714af5c887c875e8a2906389b08e8c8b',
    '0010008000b000a82098003c08000a9820958aa10a3e04b0205f123f5e3c5feb',
]
Hs = [bytes.fromhex(x) for x in H_HEX]

print('=== per-byte values across the 3 live H signings ===')
print('byte |  H0    H1    H2   | distinct | bit-patterns (LSB->MSB)')
for i in range(32):
    vals = [h[i] for h in Hs]
    pats = ['%08s' % format(v, 'b')[::-1] for v in vals]
    print(' %2d  |  %02x    %02x    %02x  |    %d     | %s'
          % (i, vals[0], vals[1], vals[2], len(set(vals)),
             ' '.join(p.replace('0', '.').replace('1', '#') for p in pats)))

print()
print('=== dword views ===')
for name, fmt in (('BE', '>4I'), ('LE', '<4I')):
    print(' %s:' % name)
    for i, h in enumerate(Hs):
        w = struct.unpack(fmt, h)
        print('   H%d: %s' % (i, ' '.join('%08x' % x for x in w)))

print()
print('=== ascending? (is H a sorted table?) ===')
for i, h in enumerate(Hs):
    be = struct.unpack('>8I', h)
    le = struct.unpack('<8I', h)
    print('  H%d BE sorted: %s | LE sorted: %s'
          % (i, list(be) == sorted(be), list(le) == sorted(le)))

print()
print('=== how many bytes would a uniform-random 32-B value have with these stats? ===')
tot = sum(1 for h in Hs for b in h)
zeros = sum(1 for h in Hs for b in h if b == 0)
sub16 = sum(1 for h in Hs for b in h if b < 0x10)
print('  observed: zeros %d/96 (%.1f%%), <0x10 %d/96 (%.1f%%)'
      % (zeros, 100.0 * zeros / 96, sub16, 100.0 * sub16 / 96))
print('  uniform  : zeros %.1f/96, <0x10 %.1f/96' % (96 / 256.0, 96 * 16 / 256.0))
print('  => zeros %.0fx and small-bytes %.0fx more frequent than uniform'
      % ((zeros / 96) / (1 / 256.0), (sub16 / 96) / (16 / 256.0)))