# det3.py - proper per-signing pairing + descriptor dump + same-second test.
#  1. segment every signing in the EMIT trace (field loop 36,5,4,8,1,1 + #10)
#  2. identify each signing's FINAL blob by matching the 48-dword last-write map
#     of every sink against all 8 nsign records -> gives the true CALL SECOND
#  3. dump #0/#2/#4/#8 for each signing; group by (map, second)
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

DEV = os.path.join(os.path.dirname(HERE), 'device')
evs = [e for e in json.load(open(os.path.join(DEV, 'whcap_hits7.json'),
                                 encoding='utf-8')) if e.get('tag') == 'emit']
print('emit events:', len(evs))

# ---------------- sinks: pos -> last val ----------------
sinks = {}
for e in evs:
    sinks.setdefault(e['sink'], {})[int(e['pos'], 16)] = int(e['val'], 16)
print('distinct sinks:', len(sinks))

# ---------------- nsign records ----------------
log = open(os.path.join(DEV, 'adj9_wh4.log'), 'rb').read().decode(
    'utf-8', errors='replace')
recs = re.findall(r'###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n'
                  r'text: len=\d+\nnano_out=\d+\nhex=([0-9a-f]+)', log)
recs = [(int(ts), bytes.fromhex(hx)) for ts, hx in recs]
print('nsign records:', len(recs))

blob_by_sink = {}
for ts, blob in recs:
    dw = list(struct.unpack('>48I', blob))
    sec = None
    for cand in range(ts // 1000 - 40, ts // 1000 + 5):
        if make_header(cand) == blob[:16]:
            sec = cand
            break
    for sk, pm in sinks.items():
        ok = all(pm.get(i) == dw[i] for i in range(48))
        if ok:
            blob_by_sink[sk] = (ts, blob, sec)
print('sinks carrying a full nsign blob:', len(blob_by_sink))
for sk, (ts, blob, sec) in blob_by_sink.items():
    print('   sink %s -> blob %s sec=%s' % (sk[-6:], blob.hex()[:16], sec))

# ---------------- segment signings ----------------
LENS = [36, 5, 4, 8, 1, 1]
signings = []
i = 0
n = len(evs)
while i < n - 60:
    start = i
    try:
        vals = {}
        prev = None
        ok = True
        j = i
        for L in LENS:
            sk = evs[j]['sink']
            if sk == prev:
                ok = False
                break
            run = []
            for k in range(L):
                e = evs[j + k]
                if e['sink'] != sk or int(e['pos'], 16) != k:
                    ok = False
                    break
                run.append(int(e['val'], 16))
            if not ok:
                break
            vals[L] = run
            prev = sk
            j += L
        if not ok or vals[5][0] != 0xFAD0F10D:
            i += 1
            continue
        # #10: variable run, head must be 'KlcA'
        if int(evs[j]['val'], 16) != 0x4B6C6341:
            i += 1
            continue
        sk10 = evs[j]['sink']
        run10, pos, jj = [], 0, j
        while jj < n and evs[jj]['sink'] == sk10 and int(evs[jj]['pos'], 16) == pos:
            run10.append(int(evs[jj]['val'], 16))
            pos += 1
            jj += 1
        b10 = b''.join(struct.pack('>I', v) for v in run10)
        m = re.search(rb'(click|session)$', b10)
        signings.append({
            'ev': start, 'd0': vals[36], 'd9': vals[5], 'd8': vals[4],
            'd4': vals[8], 'd2': vals[1][0], 'd7': vals[1][0], 'd10': run10,
            'kind': m.group(1).decode() if m else '?',
        })
        i = jj
    except (AssertionError, IndexError):
        i += 1
        continue
print()
print('signings segmented:', len(signings))
for k, s in enumerate(signings):
    print('--- S%d %s ev=%d ---' % (k, s['kind'], s['ev']))
    print('   #0 %s' % b''.join(struct.pack('>I', v) for v in s['d0']).hex())
    print('   #2 %08x   #8 %s' % (s['d2'],
          b''.join(struct.pack('>I', v) for v in s['d8']).hex()))
    print('   #4 %s' % b''.join(struct.pack('>I', v) for v in s['d4']).hex())
print()
print('--- descriptor equality matrix ---')
for a in range(len(signings)):
    for b in range(a + 1, len(signings)):
        A, B = signings[a], signings[b]
        print('S%d/%s vs S%d/%s: #0=%s #2=%s #4=%s #8=%s #10=%s' % (
            a, A['kind'], b, B['kind'],
            'EQ' if A['d0'] == B['d0'] else 'DIFF',
            'EQ' if A['d2'] == B['d2'] else 'DIFF',
            'EQ' if A['d4'] == B['d4'] else 'DIFF',
            'EQ' if A['d8'] == B['d8'] else 'DIFF',
            'EQ' if A['d10'] == B['d10'] else 'DIFF'))
json.dump([{k: (v if k != 'd10' else len(v)) for k, v in s.items()}
           for s in signings],
          open(os.path.join(HERE, 'det3_result.json'), 'w'), indent=1)
