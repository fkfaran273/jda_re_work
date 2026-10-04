# h6_tail.py - retest #4 structure on the 6 ADJUST signings only (S4..S9), then
# test whether #4's 24-byte tail is a digest of (head8 || own inputs).
import hashlib
import itertools
import json
import os
import struct
import zlib

REV = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(REV, 'all_signings.json'), encoding='utf-8'))
adj = [s for s in A if not s['d10'].startswith('504b')]
print('adjust signings: %d (from %d total)' % (len(adj), len(A)))
Hs = [bytes.fromhex(s['d4']) for s in adj]
PW2 = {1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80}
allb = b''.join(Hs)
n = len(allb)
print('=== #4 stats on the %d ADJUST signings (uniform: zeros .4%%, <0x10 6.2%%, pow2 3.1%%) ==='
      % len(Hs))
print('  zeros %4.1f%%   <0x10 %4.1f%%   pow2 %4.1f%%'
      % (100.0 * allb.count(0) / n,
         100.0 * sum(1 for b in allb if b < 0x10) / n,
         100.0 * sum(1 for b in allb if b in PW2) / n))
print('  per-byte-position:')
for i in range(32):
    col = [h[i] for h in Hs]
    tag = 'HEAD' if i < 8 else ''
    print('   %2d: zeros %d/%d distinct %d  %s  %s'
          % (i, col.count(0), len(Hs), len(set(col)),
             ' '.join('%02x' % v for v in col), tag))
c0 = 0
bybyte = {}
for i in range(32):
    for bit in range(8):
        vals = [(h[i] >> bit) & 1 for h in Hs]
        if not any(vals):
            c0 += 1
            bybyte.setdefault(i, []).append(bit)
print('  always-0 bits: %d/256 (chance %.2f) at %s'
      % (c0, 256 * 0.5 ** len(Hs), bybyte))

# ---------------- tail-vs-digest battery ----------------
print()
print('=== is the 24-byte tail a digest of (head8 || own inputs)? ===')


def digs(buf):
    d = {'md5': hashlib.md5(buf).digest(), 'sha1': hashlib.sha1(buf).digest(),
         'sha256': hashlib.sha256(buf).digest(), 'sha512': hashlib.sha512(buf).digest(),
         'crc32be': struct.pack('>I', zlib.crc32(buf)),
         'adlerbe': struct.pack('>I', zlib.adler32(buf))}
    h = 0x811C9DC5
    for c in buf:
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    d['fnv1a'] = struct.pack('>I', h)
    j = 0
    for c in buf:
        j = (j * 31 + c) & 0xFFFFFFFF
    d['java'] = struct.pack('>I', j)
    return d


for k, s in enumerate(adj):
    H = bytes.fromhex(s['d4'])
    head, tail = H[:8], H[8:]
    parts = {
        'd10': bytes.fromhex(s['d10']), 'd0': bytes.fromhex(s['d0']),
        'd8': bytes.fromhex(s['d8']), 'd9': bytes.fromhex(s['d9']),
        'd2': bytes.fromhex(s['d2']), 'head': head, 'd7': bytes.fromhex(s['d7']),
    }
    names = list(parts)
    msgs = {}
    for r in (1, 2, 3):
        for combo in itertools.permutations(names, r):
            msgs['+'.join(combo)] = b''.join(parts[c] for c in combo)
    hits = []
    for mname, mbuf in msgs.items():
        for dname, dv in digs(mbuf).items():
            if tail in dv:
                hits.append('%s(%s) contains tail' % (dname, mname))
            if head in dv:
                hits.append('%s(%s) contains head' % (dname, mname))
    print('  S%-2d tail=%s : %s' % (k, tail.hex()[:24],
                                    ' | '.join(hits[:4]) if hits else 'NO match (%d msgs x 8 digests)'
                                    % len(msgs)))