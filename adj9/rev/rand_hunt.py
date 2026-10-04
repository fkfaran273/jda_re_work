# rand_hunt.py - can #0/#2/#4 be drawn from the per-second PRNG stream?
# Reproduce each signing's descriptors with #2/#7 kept separate, then search
# Random3(sec) raw streams (both variants: v>>1 and full 32-bit v) for the
# observed dwords.
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header, Random3

M31 = 2147483647


class Random3Full(Random3):
    """Same recurrence, but yields the full 32-bit sum (v), not v>>1."""
    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o


DEV = os.path.join(os.path.dirname(HERE), 'device')
evs = [e for e in json.load(open(os.path.join(DEV, 'whcap_hits7.json'),
                                 encoding='utf-8')) if e.get('tag') == 'emit']

# emission order with per-field identity (VA_ORDER): #0,#9,#8,#4,#2,#7,#10,#5,#6
SEQ = [(0, 36), (9, 5), (8, 4), (4, 8), (2, 1), (7, 1), (10, None), (5, 1), (6, 1)]
signings = []
i, n = 0, len(evs)
while i < n - 60:
    start = i
    try:
        prev, j, got = None, i, {}
        ok = True
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
        signings.append({'kind': m.group(1).decode() if m else '?',
                         'ev': start, 'd0': got[0], 'd2': got[2], 'd4': got[4],
                         'd7': got[7], 'd8': got[8], 'd10': got[10]})
        i = j
    except (AssertionError, IndexError):
        i += 1
        continue

print('signings:', len(signings))
CUES = {}
for k, s in enumerate(signings):
    print('S%d %s ev=%d  #2=%08x #7=%08x' % (k, s['kind'], s['ev'],
                                             s['d2'][0], s['d7'][0]))
    print('   #0 dw: %s' % ' '.join('%08x' % v for v in s['d0']))
    print('   #4 dw: %s' % ' '.join('%08x' % v for v in s['d4']))
    CUES['S%d' % k] = set(s['d0']) | set(s['d4']) | {s['d2'][0]}

# ---- hunt: which seconds' PRNG stream contains these values? ----
GOLDEN_SEC = 1789240512
lo, hi = GOLDEN_SEC - 8, GOLDEN_SEC + 8
for label, cls in (('v>>1', Random3), ('full-v', Random3Full)):
    print()
    print('--- stream variant %s: searching sec %d..%d (4000 draws) ---'
          % (label, lo, hi))
    for sec in range(lo, hi + 1):
        R = cls(sec)
        pos = {}
        for idx in range(4000):
            w = R.next() & 0xFFFFFFFF
            if w not in pos:
                pos[w] = idx
        hits = []
        for name, vals in CUES.items():
            f = [('%08x@%d' % (v, pos[v])) for v in vals if v in pos]
            if f:
                hits.append('%s:%d/%d %s' % (name, len(f), len(vals), f[:6]))
        if hits:
            print('  sec=%d  %s' % (sec, ' | '.join(hits)))
print()
# also: is #2 a header word of some near second?
print('--- #2 vs header words of nearby seconds ---')
for sec in range(lo, hi + 1):
    hw = list(struct.unpack('>4I', make_header(sec)))
    for k, s in enumerate(signings):
        if s['d2'][0] in hw:
            print('  S%d #2 %08x == header[%d] of sec %d'
                  % (k, s['d2'][0], hw.index(s['d2'][0]), sec))
json.dump([{k: (v if k != 'd10' else len(v)) for k, v in s.items()}
           for s in signings],
          open(os.path.join(HERE, 'rand_hunt_result.json'), 'w'), indent=1)