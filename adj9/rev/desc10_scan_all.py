# desc10_scan_all.py - find EVERY captured desc10 in the device logs and measure it.
#
# Rationale: every desc10 begins with the adj_verification anchor
# "KlcAG2cbAAsKSl1KVi0FGiJbDHMI" and ends with the envelope block2 tail
# <activity_kind> + "android5.7.0" + "10" + "5.0.0" (plus optional NUL padding).
# So a raw byte scan over the logs recovers every claim set ever captured, its
# length, and its activity_kind - with no EMIT trace and no descriptors needed.
#
# This is the decisive test for slice 107's prediction:
#   attribution (21 keys) => unpadded 246 B, padded 248 B.
# If a 246/248 B run with activity_kind="attribution" exists in the logs, the
# claim set is CONFIRMED from live data; if only session/click lengths appear, the
# prediction stays unverified.
import glob
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
ANCHOR = b'KlcAG2cbAAsKSl1KVi0FGiJbDHMI'
TAIL = b'android5.7.0105.0.0'

files = []
for pat in ('adj9_wh*.log', 'whcap_hits*.json', 'desc10*.json', 'adj9_*cap*.log',
            'adj9_full.log', 'adj9_hp*.log', 'oracle*.log', 'probe*.log',
            'dev_capture.log', 'live_probe.log', '*.saz'):
    files += sorted(glob.glob(os.path.join(DEV, pat)))
files += [os.path.join(HERE, 'desc10_runs.json'),
          os.path.join(HERE, 'all_signings.json'),
          os.path.join(HERE, 'wh4_records.json')]
files = [f for f in dict.fromkeys(files) if os.path.exists(f)]
CAP = 120 * 1024 * 1024
print('scanning %d prioritised files for the desc10 anchor' % len(files), flush=True)
rows = {}
scanned = 0
for p in files:
    try:
        if os.path.getsize(p) > CAP:
            print('  (skip, >%dMB) %s' % (CAP // 1024 // 1024, os.path.basename(p)),
                  flush=True)
            continue
        data = open(p, 'rb').read()
    except Exception as e:
        print('  (unreadable) %s: %s' % (os.path.basename(p), e), flush=True)
        continue
    scanned += 1
    print('  read %-28s %8.1f MB' % (os.path.basename(p),
                                      len(data) / 1048576.0), flush=True)
    start = 0
    while True:
        i = data.find(ANCHOR, start)
        if i < 0:
            break
        start = i + 1
        j = data.find(TAIL, i)
        if j < 0 or j - i > 4000:
            continue
        end = j + len(TAIL)
        raw = data[i:end]
        # strip trailing NULs the native pads with
        nz = len(raw) - len(raw.rstrip(b'\x00'))
        # activity_kind = the token immediately before the c/sdk tail
        pre = raw[:raw.find(TAIL)]
        kind = None
        for k in (b'attribution', b'session', b'click', b'event'):
            if pre.endswith(k):
                kind = k.decode()
                break
        if kind is None:
            continue
        unpadded = len(raw.rstrip(b'\x00'))
        key = (kind, unpadded, 'padded %d' % ((unpadded + 3) // 4 * 4))
        rows.setdefault(key, set()).add(os.path.basename(p))

print('files read: %d' % scanned)
print()
print('=== every distinct captured desc10 shape ===')
print('%-12s %-9s %-12s %s' % ('activity', 'bytes', 'padded', 'seen in'))
for (kind, n, pad) in sorted(rows, key=lambda k: (k[0], k[1])):
    print('%-12s %-9d %-12s %s' % (kind, n, pad, sorted(rows[(kind, n, pad)])[:3]))
print()
print('=== slice-107 prediction check ===')
att = [k for k in rows if k[0] == 'attribution']
if att:
    print('  attribution claim sets FOUND: %s' % sorted(att))
    for k in sorted(att):
        print('    %s -> unpadded %d (predicted 246)  %s'
              % (k[0], k[1], 'CONFIRMED' if k[1] == 246 else 'differs'))
else:
    print('  NO attribution desc10 in the logs -> prediction stays UNVERIFIED')
    print('  (session/click only: %s)' % sorted({k[0] for k in rows}))