# recheck3.py - the sharp d0 test: is d0's repeated 16-B tile the signing's own
# 16-byte blob header (Random3-derived, already computable)? plus d2 origin hunt.
import json
import os
import struct
import sys

REV = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REV)
from header_gen import make_header, Random3

A = json.load(open(os.path.join(REV, 'all_signings.json'), encoding='utf-8'))
FIN = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
golden_blob = bytes.fromhex(FIN['target']['blob_hex'])
golden_hdr = golden_blob[:16]
golden_sec = FIN['target']['second']
print('golden blob hdr =', golden_hdr.hex(), ' sec =', golden_sec)
print()

print('=== per-signing d0 shape: prefix dword + 16-B tile ===')
shapes = []
for k, s in enumerate(A):
    w = list(struct.unpack('>36I', bytes.fromhex(s['d0'])))
    # find the smallest period p in the tail region
    p = None
    for cand in range(1, 18):
        if all(w[x] == w[x - cand] for x in range(cand + 1, 36)):
            p = cand
            break
    tile = b''.join(struct.pack('>I', v) for v in w[1:1 + p])
    prefix = struct.pack('>I', w[0])
    shapes.append((prefix, tile))
    print('  S%-2d %-18s prefix=%s tile=%s hdr?=%s'
          % (k, s['src'], prefix.hex(), tile.hex(),
             'YES' if tile == golden_hdr else 'no'))

print()
print('=== does ANY signing\'s tile equal a make_header(sec) near the golden burst? ===')
for sec in range(golden_sec - 6, golden_sec + 7):
    h = make_header(sec)
    hit = [k for k, (p, t) in enumerate(shapes) if t == h or p + t[:12] == h]
    print('  sec %d hdr %s  hits=%s' % (sec, h.hex(), hit))

print()
print('=== is the tile make_header(X) for X = any sec in +-20000 (fast scan) ===')
found = {}
for sec in range(golden_sec - 20000, golden_sec + 20000):
    h = make_header(sec)
    for k, (p, t) in enumerate(shapes):
        if t == h:
            found.setdefault(k, []).append(sec)
print('  tile==make_header(sec) hits:', found or 'NONE')
