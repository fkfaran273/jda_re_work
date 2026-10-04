# final_d014.py - consolidated verification table for #0/#2/#4/#7/#8/#9 across all
# 10 harvested Adjust signings (the report's evidence base).
import json
import os
import struct

REV = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(REV, 'all_signings.json'), encoding='utf-8'))
print('signings: %d' % len(A))
print()
print('slot   | evidence')
print('-------|---------------------------------------------------------------')
heads = {}
print('#10    | lengths: %s' % sorted({len(bytes.fromhex(s["d10"])) for s in A}))
first = {bytes.fromhex(s['d10'])[:4] for s in A}
print('       | first4: %s  (4b6c6341 = "KlcA" claims)' % {f.hex() for f in first})
print('#7     | vs len(#10) unpadded: %s'
      % [('%x' % struct.unpack('>I', bytes.fromhex(s['d7']))[0],
          len(bytes.fromhex(s['d10']).rstrip(b'\0'))) for s in A])
print('#8     | distinct: %d  %s'
      % (len({s['d8'] for s in A}), list({s['d8'] for s in A})[0]))
print('#9     | distinct: %d  %s'
      % (len({s['d9'] for s in A}), list({s['d9'] for s in A})[0]))
print('#5/#6  | distinct: %s / %s'
      % ({s['d5'] for s in A}, {s['d6'] for s in A}))
print('#2     | 10 values: %s' % [s['d2'][:8] for s in A])
print()

print('=== #0 shape per signing (prefix + repeated 16-B tile) ===')
for k, s in enumerate(A):
    w = list(struct.unpack('>36I', bytes.fromhex(s['d0'])))
    best = None
    for p in range(1, 18):
        for o in range(0, 6):
            if all(w[x] == w[x - p] for x in range(o + p, len(w))):
                if best is None or (o + p) < sum(best):
                    best = (o, p)
    o, p = best
    pref = b''.join(struct.pack('>I', v) for v in w[:o])
    tile = b''.join(struct.pack('>I', v) for v in w[o:o + p])
    print('  S%-2d %-18s prefix=%-10s tile=%s  (%d fresh dwords)'
          % (k, s['src'], pref.hex() or '(none)', tile.hex(), o + p))

print()
print('=== #4 head8 groups (same head => same key/algo context?) ===')
for k, s in enumerate(A):
    h = bytes.fromhex(s['d4'])
    heads.setdefault(h[:8].hex(), []).append(k)
for hd, ks in heads.items():
    print('  %s : signings %s' % (hd, ks))
print()
print('=== #4 head8 vs tail24 summary ===')
for k, s in enumerate(A):
    h = bytes.fromhex(s['d4'])
    print('  S%-2d head=%s tail=%s' % (k, h[:8].hex(), h[8:].hex()))

print()
print('=== #0 tile/prefix reuse ACROSS signings? ===')
tiles = {}
for k, s in enumerate(A):
    w = list(struct.unpack('>36I', bytes.fromhex(s['d0'])))
    tiles.setdefault(s['d0'], []).append(k)
print('  distinct #0 values: %d of %d -> %s'
      % (len(tiles), len(A), 'ALL DIFFERENT' if len(tiles) == len(A) else 'SOME SHARED'))
sh = [ks for ks in tiles.values() if len(ks) > 1]
print('  shared groups: %s' % (sh or 'none'))