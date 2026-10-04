# h24_rel.py - are #2 and #4 two views of ONE per-call record, and is #2 derivable?
#
# Slice 104: in the same-second, same-claims pair (desc_det idx 0 vs 2) BOTH #2
# and #4 differ. If they come from one context record, #2 should be some function
# of #4 (or of the material #4 is built from). This tests that directly, plus a
# bit-field reading of #4's structured head.
import json
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FD = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
DET = json.load(open(os.path.join(HERE, 'desc_det_result.json'), encoding='utf-8'))
ALS = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))


def be(vals):
    return b''.join(struct.pack('>I', v & 0xffffffff) for v in vals)


S = []          # (tag, d4, d2, d0)
for d in FD['descs']:
    if d['build_idx'] == 4:
        S.append(('golden', bytes.fromhex(d['data_hex']), None, None))
for d in FD['descs']:
    if d['build_idx'] == 2:
        S[-1] = (S[-1][0], S[-1][1], int(d['data_hex'], 16), None)
for d in FD['descs']:
    if d['build_idx'] == 0:
        S[-1] = (S[-1][0], S[-1][1], S[-1][2], bytes.fromhex(d['data_hex']))
for i, e in enumerate(DET):
    S.append(('det[%d]' % i, be(e['d4']), e['d2'], be(e['d0'])))
for i, s in enumerate(ALS):
    if s.get('d4'):
        S.append(('als[%d]' % i, bytes.fromhex(s['d4']),
                  int(s['d2'], 16), bytes.fromhex(s['d0']) if s.get('d0') else None))

print('samples: %d' % len(S))
print()

# ---- 1. is #2 a function of #4? ---------------------------------------------
print('=== (1) candidate #2 derivations from #4 ===')
funcs = {
    'crc32(d4)': lambda b: zlib.crc32(b) & 0xffffffff,
    'adler32(d4)': lambda b: zlib.adler32(b) & 0xffffffff,
    'fnv1a(d4)': lambda b: __import__('functools').reduce(
        lambda h, c: ((h ^ c) * 0x01000193) & 0xffffffff, b, 0x811c9dc5),
    'sum(dwords)': lambda b: sum(struct.unpack('>8I', b)) & 0xffffffff,
    'xor(dwords)': lambda b: __import__('functools').reduce(
        lambda a, c: a ^ c, struct.unpack('>8I', b)),
    'dw0': lambda b: struct.unpack('>8I', b)[0],
    'dw1': lambda b: struct.unpack('>8I', b)[1],
    'dw7': lambda b: struct.unpack('>8I', b)[7],
    'popcount(d4)': lambda b: sum(bin(c).count('1') for c in b),
}
known = [(t, d4, d2) for t, d4, d2, _ in S if d2 is not None]
print('  samples with both #2 and #4: %d' % len(known))
for name, fn in funcs.items():
    hits = sum(1 for _, d4, d2 in known if (fn(d4) & 0xffffffff) == d2)
    print('  %-16s matches %-3d / %d' % (name, hits, len(known)))
print()

# ---- 2. are #2 / #4 / #0 co-varying (one record)? ---------------------------
print('=== (2) do #2, #4, #0 vary together? ===')
pairs = [(t, d4, d2, d0) for t, d4, d2, d0 in S if d2 is not None and d0 is not None]
print('  samples with #2, #4 and #0: %d' % len(pairs))
for i in range(len(pairs)):
    for j in range(i + 1, len(pairs)):
        a, b = pairs[i], pairs[j]
        same4 = a[1] == b[1]
        same2 = a[2] == b[2]
        same0 = a[3] == b[3]
        rel = 'consistent (all three move together)' if (same4 == same2 == same0) \
            else 'INCONSISTENT'
        if not same4 or (same4 and same2 and same0):
            print('  %-9s vs %-9s  #4=%s #2=%s #0=%s  -> %s'
                  % (a[0], b[0], 'EQ' if same4 else 'DIFF',
                     'EQ' if same2 else 'DIFF', 'EQ' if same0 else 'DIFF', rel))
print()

# ---- 3. bit-field reading of #4's head -------------------------------------
print('=== (3) #4 head as a bit-field (bytes 0..7) ===')
print('%-9s %-17s %s' % ('tag', 'head(hex)', 'set-bit positions (0..63)'))
for t, d4, _, _ in S:
    h = d4[:8]
    bits = [i for i in range(64) if (int.from_bytes(h, 'big') >> (63 - i)) & 1]
    print('%-9s %-17s %s' % (t, h.hex(), bits))
print()
print('popcount of each head byte, and whether bytes 0..1 look like lengths:')
for t, d4, _, _ in S:
    h = d4[:8]
    print('  %-9s %s  b0=%02x b1=%02x  b0+b1=%d' %
          (t, ' '.join('%02x' % c for c in h),
           h[0], h[1], h[0] + h[1]))