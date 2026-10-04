# trace_survey.py - find every EMIT trace and harvest all #4 (H) values, to grow
# the H sample set for the structural (bit-packed?) test.
import glob
import json
import os
import struct

DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
BIG = 60 * 1024 * 1024

traces = []
for p in glob.glob(os.path.join(DEV, '*.json')) + glob.glob(os.path.join(REV, '*.json')):
    try:
        if os.path.getsize(p) > BIG:
            continue
        d = json.load(open(p, encoding='utf-8'))
    except Exception:
        continue
    if isinstance(d, list) and any(
            isinstance(e, dict) and e.get('tag') == 'emit' for e in d[:200]):
        traces.append((p, len(d)))
print('EMIT traces found:')
for p, n in traces:
    print('   %-28s %d events' % (os.path.basename(p), n))

# segment signings in each trace and pull #4 (8 dwords, 4th field of the field loop)
SEQ = [(0, 36), (9, 5), (8, 4), (4, 8), (2, 1), (7, 1), (10, None), (5, 1), (6, 1)]
Hs = {}
for p, _ in traces:
    evs = [e for e in json.load(open(p, encoding='utf-8'))
           if isinstance(e, dict) and e.get('tag') == 'emit']
    i, n = 0, len(evs)
    found = 0
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
            h = b''.join(struct.pack('>I', v) for v in got[4])
            Hs.setdefault(h.hex(), []).append('%s@%d' % (os.path.basename(p), i))
            found += 1
            i = j
        except (AssertionError, IndexError):
            i += 1
            continue
    print('   %-28s signings with #4: %d' % (os.path.basename(p), found))

print()
print('distinct #4 (H) values: %d' % len(Hs))
for h, where in Hs.items():
    print('   %s  %s' % (h, where[:3]))
json.dump(Hs, open(os.path.join(REV, 'h_samples.json'), 'w'), indent=1)