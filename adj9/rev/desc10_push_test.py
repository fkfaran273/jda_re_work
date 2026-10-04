# desc10_push_test.py - PROVE the push_token addition (slice 105).
#
# The captures contain FOUR desc10 lengths: 360 (session), 388 (click+1 pad),
# 504 (session+token), 532 (click+token+2 pad). The law explained only the first
# two. Test: `push_token` is a plain sorted profile claim + NUL padding to a
# 4-byte multiple => one rebuilt law reproduces ALL FOUR byte-exactly.
#
# Pairing: each capture belongs to a DIFFERENT signing, so the per-signing values
# (android_uuid, created_at, push_token) are recovered from the capture by generic
# regex / known-anchor slicing - never by position guessing - and the law is then
# asserted byte-for-byte against that capture.
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from desc10_law import build_desc10, desc10_keys, pad4

ALS = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))
W = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
DEV = os.path.join(os.path.dirname(HERE), 'device')

CAPS = {}
for s in ALS:
    if s.get('d10'):
        CAPS.setdefault(len(s['d10']) // 2, []).append(s['d10'].lower())

UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
ISO_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}')

si = W['sign_inputs'][W['golden_sign_input_idx']]
sbase = {}
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        sbase[k] = v
cbase = {}
with open(os.path.join(DEV, 'adj9_wh4.log'), encoding='utf-8', errors='replace') as f:
    for ln, line in enumerate(f, 1):
        if ln == 286234:
            m = re.search(r'\{(.*)\}', line.strip())
            cbase = dict(re.findall(r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*), ?',
                                    m.group(1) + ','))
            break
cbase.setdefault('adj_signing_id', '1500000')
cbase.setdefault('headers_id', '10')
cbase.setdefault('native_version', '5.0.0')


def val_for(hexstr, base):
    """Recover this capture's own per-signing values; keep the shared ones."""
    txt = bytes.fromhex(hexstr).decode('latin1')
    v = dict(base)
    m = UUID_RE.search(txt)
    if m:
        v['android_uuid'] = m.group(0)
    av = base['app_version']
    i = txt.index(av) + len(av)
    m2 = ISO_RE.search(txt, i)
    if m2:
        v['created_at'] = m2.group(0)
    pk = base['package_name']
    a = txt.index(pk) + len(pk)
    # push_token sorts immediately after package_name, so it runs up to whichever
    # law key follows it: adj_signing_id for session, referrer for click.
    stop = base.get('referrer') if base.get('referrer') else None
    if stop:
        b = txt.index(stop, a)
    else:
        b = txt.index(base.get('adj_signing_id', '1500000'), a)
    tok = txt[a:b]
    if tok:
        v['push_token'] = tok
    return v, len(tok)


fails = []
print('=== law reproduction of every captured desc10 ===')
for L in sorted(CAPS):
    base = sbase if L in (360, 504) else cbase
    kind = 'session' if L in (360, 504) else 'click'
    for hx in CAPS[L]:
        v, tlen = val_for(hx, base)
        try:
            got = build_desc10(v, kind)
        except KeyError as e:
            print('  %4d B %-8s KeyError %s' % (L, kind, str(e)[:80]))
            fails.append(L)
            continue
        gb = pad4(got.encode('latin1'))
        ok = gb.hex() == hx
        print('  %4d B %-8s token=%-3d law=%3dB padded=%3dB  %-10s uuid=%s'
              % (L, kind, tlen, len(got), len(gb),
                 'BYTE-EXACT' if ok else 'FAIL', v['android_uuid'][:8]))
        if not ok:
            fails.append(L)
            exp = bytes.fromhex(hx)
            for i in range(min(len(gb), len(exp))):
                if gb[i] != exp[i]:
                    print('        first diff at byte %d:\n          law   =%r\n'
                          '          expect=%r' % (i, gb[max(0, i - 16):i + 8],
                                                   exp[max(0, i - 16):i + 8]))
                    break

print('\n=== key counts ===')
print('  session, no token : %d keys' % len(desc10_keys('session', sbase)))
print('  session, +token   : %d keys'
      % len(desc10_keys('session', dict(sbase, push_token='X'))))
print('  click, no token   : %d keys' % len(desc10_keys('click', cbase)))
print('  click, +token     : %d keys'
      % len(desc10_keys('click', dict(cbase, push_token='X'))))
print('\n=== RESULT: %s ==='
      % ('PASS - all %d captures reproduced byte-exactly'
         % sum(len(v) for v in CAPS.values())
         if not fails else 'FAIL for lengths %s' % sorted(set(fails))))