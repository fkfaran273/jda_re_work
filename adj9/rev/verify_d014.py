# verify_d014.py - OFFLINE verification of #0/#2/#4 (the goal: pure-Python signer).
#  1. structure: #0 = prefix + 16-B tile repeated (minimal fresh surface)
#  2. #7 = len(#10), #8 constant, #9 = cert, #5/#6 zero  (the "known" slots)
#  3. digest battery: is A / B(tile) / #2 / #4 a computable function of the
#     signing's own inputs (desc10, H, cert, timestamps, second)?
import hashlib
import json
import os
import re
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

DEV = os.path.join(os.path.dirname(HERE), 'device')
evs = [e for e in json.load(open(os.path.join(DEV, 'whcap_hits7.json'),
                                 encoding='utf-8')) if e.get('tag') == 'emit']
SEQ = [(0, 36), (9, 5), (8, 4), (4, 8), (2, 1), (7, 1), (10, None), (5, 1), (6, 1)]

signings = []
i, n = 0, len(evs)
while i < n - 60:
    start, prev, j, got, ok = i, None, i, {}, True
    try:
        for bidx, L in SEQ:
            sk = evs[j]['sink']
            if sk == prev or (L is None and int(evs[j]['val'], 16) != 0x4B6C6341):
                ok = False
                break
            run = []
            if L is None:
                pos = 0
                while j + pos < n and evs[j + pos]['sink'] == sk \
                        and int(evs[j + pos]['pos'], 16) == pos:
                    run.append(int(evs[j + pos]['val'], 16))
                    pos += 1
            else:
                for k in range(L):
                    e = evs[j + k]
                    if e['sink'] != sk or int(e['pos'], 16) != k:
                        ok = False
                        break
                    run.append(int(e['val'], 16))
            if not ok:
                break
            got[bidx] = run
            prev = sk
            j += len(run)
        if not ok or got[9][0] != 0xFAD0F10D:
            i += 1
            continue
        b10 = b''.join(struct.pack('>I', v) for v in got[10])
        m = re.search(rb'(click|session)$', b10)
        ca = re.search(rb'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\+\d{4})', b10)
        signings.append({'kind': m.group(1).decode() if m else '?', 'ev': start,
                         'd0': got[0], 'd2': got[2], 'd4': got[4], 'd7': got[7],
                         'd8': got[8], 'd9': got[9], 'd10': got[10],
                         'created': ca.group(1).decode() if ca else None})
        i = j
    except (AssertionError, IndexError):
        i += 1
        continue

print('=' * 78)
print('1. #0 STRUCTURE - prefix + repeated 16-B tile (minimal fresh surface)')
print('=' * 78)
for k, s in enumerate(signings):
    w = s['d0']
    best = None
    for p in range(1, 18):
        for o in range(0, 6):
            if all(w[x] == w[x - p] for x in range(o + p, len(w))):
                if best is None or (o + p) < sum(best):
                    best = (o, p)
    o, p = best
    tile = b''.join(struct.pack('>I', v) for v in w[o:o + p])
    prefix = b''.join(struct.pack('>I', v) for v in w[:o])
    print('S%d %-7s period=%d offset=%d  prefix=%d B  tile=%s  tile x%.2f'
          % (k, s['kind'], p, o, len(prefix), tile.hex(), (len(w) - o) / p))
    print('     prefix hex: %s' % prefix.hex())
    s['tile'], s['prefix'], s['period'] = tile, prefix, p

print()
print('=' * 78)
print('2. KNOWN SLOTS (laws)')
print('=' * 78)
print('   #7 == len(#10) bytes?  %s'
      % all(s['d7'][0] == len(b''.join(struct.pack('>I', v) for v in s['d10'])
                             .rstrip(b'\0')) for s in signings))
print('   #7 vs #10: %s'
      % [(hex(s['d7'][0]), len(s['d10']) * 4) for s in signings])
print('   #8 constant?     %s   %s'
      % (len({b''.join(struct.pack(">I", v) for v in s['d8']) for s in signings}) == 1,
         b''.join(struct.pack('>I', v) for v in signings[0]['d8']).hex()))
print('   #9 constant?     %s   %s'
      % (len({b''.join(struct.pack(">I", v) for v in s['d9']) for s in signings}) == 1,
         b''.join(struct.pack('>I', v) for v in signings[0]['d9']).hex()))
print('   #2 per signing:  %s' % ['%08x' % s['d2'][0] for s in signings])
print('   #4 raw:          %s'
      % [b''.join(struct.pack('>I', v) for v in s['d4']).hex() for s in signings])

# ---------------- 3. digest battery ----------------
print()
print('=' * 78)
print('3. DIGEST BATTERY - is prefix / tile / #2 / #4 computable from own inputs?')
print('=' * 78)


def digests(buf):
    out = {}
    for algo in ('md5', 'sha1', 'sha256', 'sha512'):
        try:
            out[algo] = hashlib.new(algo, buf).digest()
        except Exception:
            pass
    out['crc32_be'] = struct.pack('>I', zlib.crc32(buf))
    out['crc32_le'] = struct.pack('<I', zlib.crc32(buf))
    out['adler_be'] = struct.pack('>I', zlib.adler32(buf))
    h = 0x811C9DC5
    for c in buf:
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    out['fnv1a_be'] = struct.pack('>I', h)
    j = 0
    for c in buf:
        j = (j * 31 + c) & 0xFFFFFFFF
    out['java_be'] = struct.pack('>I', j)
    return out


for k, s in enumerate(signings):
    H = b''.join(struct.pack('>I', v) for v in s['d4'])
    cert = b''.join(struct.pack('>I', v) for v in s['d9'])
    d10 = b''.join(struct.pack('>I', v) for v in s['d10'])
    ca = (s['created'] or '').encode()
    cands = {'d10': d10, 'H': H, 'cert': cert, 'd10+H': d10 + H, 'H+d10': H + d10,
             'd10+cert': d10 + cert, 'ca': ca, 'd10hex': d10.hex().encode(),
             'H+d10+cert': H + d10 + cert, 'd10+H+ca': d10 + H + ca}
    targets = {'prefix': s['prefix'], 'tile': s['tile'], '#4': H}
    hits = []
    for cname, cbuf in cands.items():
        for dname, d in digests(cbuf).items():
            for tname, tv in targets.items():
                if isinstance(tv, bytes) and tv and tv in d:
                    hits.append('%s(%s) contains %s' % (dname, cname, tname))
            if any(struct.unpack('>I', d[x:x + 4])[0] == s['d2'][0]
                   for x in range(len(d) - 3)):
                hits.append('%s(%s) contains #2' % (dname, cname))
    print('S%d (%s, ca=%s): %s' % (k, s['kind'], s['created'],
                                   ' | '.join(hits) if hits else 'NO match'))

print()
print('cross-signing containment: does this signing\'s tile/prefix appear in')
print("another signing's H, cert, desc10, or #0?")
for a, A in enumerate(signings):
    for b, B in enumerate(signings):
        if a == b:
            continue
        blobB = (b''.join(struct.pack('>I', v) for v in B['d4'])
                 + b''.join(struct.pack('>I', v) for v in B['d9'])
                 + b''.join(struct.pack('>I', v) for v in B['d10'])
                 + b''.join(struct.pack('>I', v) for v in B['d0']))
        for label, val in (('tile', A['tile']), ('prefix', A['prefix'])):
            if val and val in blobB:
                print('  S%d %s found inside S%d inputs' % (a, label, b))
print('  (no output above = no cross-signing reuse)')
json.dump([{kk: (vv if kk not in ('d10', 'd0') else len(vv))
            for kk, vv in s.items() if kk not in ('tile', 'prefix')}
           for s in signings],
          open(os.path.join(HERE, 'verify_d014_result.json'), 'w'), indent=1)