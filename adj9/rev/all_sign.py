# all_sign.py - harvest ALL signings from ALL EMIT traces (full descriptors), then
# test whether #4's 24-byte tail is a digest of its own 8-byte head + own inputs.
import glob
import hashlib
import json
import os
import struct
import zlib

DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
SEQ = [(0, 36), (9, 5), (8, 4), (4, 8), (2, 1), (7, 1), (10, None), (5, 1), (6, 1)]
BIG = 120 * 1024 * 1024


def seg(evs):
    out = []
    i, n = 0, len(evs)
    while i < n - 60:
        prev, j, got, ok = None, i, {}, True
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
            def b(i_):
                return b''.join(struct.pack('>I', v) for v in got[i_])
            out.append({'src': None, 'ev': i, 'd0': b(0), 'd9': b(9), 'd8': b(8),
                        'd4': b(4), 'd2': b(2), 'd7': b(7), 'd10': b(10),
                        'd5': b(5), 'd6': b(6)})
            i = j
        except (AssertionError, IndexError):
            i += 1
            continue
    return out


all_s = []
for p in sorted(glob.glob(os.path.join(DEV, '*.json')) + glob.glob(os.path.join(REV, '*.json'))):
    try:
        if os.path.getsize(p) > BIG:
            continue
        d = json.load(open(p, encoding='utf-8'))
    except Exception:
        continue
    if not (isinstance(d, list) and any(isinstance(e, dict) and e.get('tag') == 'emit'
                                       for e in d[:200])):
        continue
    evs = [e for e in d if isinstance(e, dict) and e.get('tag') == 'emit']
    ss = seg(evs)
    for s in ss:
        s['src'] = os.path.basename(p)
    all_s.extend(ss)
print('signings harvested from all traces: %d' % len(all_s))
for k, s in enumerate(all_s):
    print('  S%-2d %-18s ev=%-6d #2=%s #4=%s #10=%dB'
          % (k, s['src'], s['ev'], s['d2'].hex(), s['d4'].hex()[:32], len(s['d10'])))
json.dump([{kk: (vv.hex() if isinstance(vv, bytes) else vv) for kk, vv in s.items()}
           for s in all_s],
          open(os.path.join(REV, 'all_signings.json'), 'w'), indent=1)