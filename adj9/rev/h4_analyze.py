# h4_analyze.py - can #4 be DERIVED? (structure + determinism)
#
# Context: #4 is not H (slice 103). It is the last non-pointer unknown besides
# #2, and it is the slot adj9_forge has been filling with a MAC. Two questions:
#   (1) STRUCTURE - the bit density rises across the record; what is it?
#   (2) DETERMINISM - is #4 a function of material we know (claims, second)?
#       If two signings share claims AND second and still differ, then #4 is a
#       process-state value, which the server cannot recompute either.
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
FD = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
DET = json.load(open(os.path.join(HERE, 'desc_det_result.json'), encoding='utf-8'))
ALS = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))
BASE = {d['build_idx']: (d['len_dw'], d['data_hex']) for d in FD['descs']}

samples = []
samples.append({'tag': 'golden', 'd4': BASE[4][1].lower(),
                'd2': BASE[2][1].lower(), 'd10': BASE[10][1].lower(),
                'sec': FD['target']['second'],
                'created_at': '2026-09-12T21:15:11.678Z+0200', 'src': 'fin_descs'})
for i, e in enumerate(DET):
    u32 = lambda v: b''.join(struct.pack('>I', x & 0xffffffff) for x in v).hex()
    samples.append({'tag': 'det[%d]' % i, 'd4': u32(e['d4']), 'd2': u32([e['d2']]),
                    'd10': BASE[10][1].lower(), 'sec': e['sec'],
                    'created_at': e['created_at'], 'kind': e['kind'],
                    'd10len': e['d10'] * 4, 'd7': e['d7']})
for i, s in enumerate(ALS):
    samples.append({'tag': 'als[%d]' % i, 'd4': s['d4'].lower(), 'd2': s['d2'].lower(),
                    'd10': s['d10'].lower(), 'sec': None, 'created_at': None,
                    'src': s.get('src')})

print('=== (1) STRUCTURE of #4 ===')
print('%-9s %-66s %-9s %s' % ('tag', '#4', 'popcnt', 'per-dword popcount'))
for s in samples[:12]:
    b = bytes.fromhex(s['d4'])
    if len(b) != 32:
        print('%-9s (len %d, skipped)' % (s['tag'], len(b) // 2))
        continue
    dw = struct.unpack('>8I', b)
    print('%-9s %-66s %-9d %s' % (s['tag'], s['d4'], sum(bin(x).count('1') for x in dw),
                                  [bin(x).count('1') for x in dw]))

print()
print('byte-level bit density of the golden #4 (0-8 ones per byte):')
gb = bytes.fromhex(BASE[4][1])
print('  bytes   : %s' % ' '.join('%02x' % c for c in gb))
print('  popcount: %s' % ' '.join('%2d' % bin(c).count('1') for c in gb))
print('  -> density INCREASES left to right; a random/hash/mac value is flat ~4.')

print()
print('=== (2) DETERMINISM: same claims + same second => same #4? ===')
groups = {}
for s in samples:
    if s.get('d10') and s.get('sec') is not None:
        groups.setdefault((s['sec'], s['d10len'] if s.get('d10len') else len(s['d10']) // 2),
                          []).append(s)
found = False
for key, ss in sorted(groups.items(), key=lambda kv: str(kv[0])):
    if len(ss) < 2:
        continue
    same10 = all(x['d10'] == ss[0]['d10'] for x in ss)
    print('  sec=%-11s claims_len=%-4s n=%d claims_identical=%s'
          % (key[0], key[1], len(ss), same10))
    for x in ss:
        print('      %-9s d4=%s  d2=%s' % (x['tag'], x['d4'], x['d2']))
    if same10:
        found = True
        d4s = {x['d4'] for x in ss}
        d2s = {x['d2'] for x in ss}
        print('      => #4 distinct: %d/%d   #2 distinct: %d/%d'
              % (len(d4s), len(ss), len(d2s), len(ss)))
        print('      => same claims AND same second, still different: #4 is NOT a'
              ' function of (claims, second)')
if not found:
    print('  no same-second same-claims pair with both #4 recorded')

print()
print('=== (3) does #4 depend on claims at all? (identical claims, any second) ===')
by10 = {}
for s in samples:
    if s.get('d10'):
        by10.setdefault(s['d10'], []).append(s)
for h, ss in by10.items():
    if len(ss) > 1:
        print('  claims %s… appear in %d signings; #4 distinct=%d'
              % (h[:24], len(ss), len({x['d4'] for x in ss})))
        for x in ss:
            print('      %-9s d4=%s' % (x['tag'], x['d4']))