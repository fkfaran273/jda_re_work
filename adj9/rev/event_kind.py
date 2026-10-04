# event_kind.py - derive the `event` claim set (the fourth and last kind).
#
# gold6.json held three shapes (session/click/attribution); `activity_kind=event`
# appears 134 times across the device logs, so the fourth kind is captured too.
# Same method as slice 107: find an event map, read its keys, and compare against
# the law blocks to derive the event claim set.
import glob
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
sys.path.insert(0, HERE)
from desc10_law import (PROFILE_COMMON, SESSION_PROFILE, CLICK_PROFILE,
                        SESSION_TAIL, CLICK_TAIL, BLOCK2, PINNED)

MAP_RE = re.compile(r'map_toString=\{([^}]*)\}')
KV_RE = re.compile(r'([A-Za-z0-9_]+)=([^,]*), ?')

files = []
for pat in ('adj9_full.log', 'dev_capture.log', 'adj9_*cap*.log', 'adj9_hp*.log',
            'oracle*.log', 'adj9_wh4.log', 'adj9_wh3.log'):
    files += sorted(glob.glob(os.path.join(DEV, pat)))
files = [f for f in dict.fromkeys(files) if os.path.exists(f)]

found = {}
for p in files:
    try:
        txt = open(p, 'rb').read().decode('utf-8', 'replace')
    except Exception:
        continue
    for m in MAP_RE.finditer(txt):
        body = m.group(1)
        kv = dict(KV_RE.findall(body + ', '))
        ak = kv.get('activity_kind')
        if ak and ak not in found:
            found[ak] = (os.path.basename(p), kv, body)

print('kinds seen in map_toString: %s' % {k: v[0] for k, v in found.items()})
print()
if 'event' not in found:
    print('no event map in the scanned logs')
    raise SystemExit(0)

src, kv, body = found['event']
keys = [k for k in re.findall(r'([A-Za-z0-9_]+)=', body) if k != 'map_order']
print('=== EVENT map (%d keys, from %s) ===' % (len(keys), src))
print('  keys: %s' % sorted(keys))
print()

lawish = set(PROFILE_COMMON) | set(SESSION_PROFILE) | set(CLICK_PROFILE) | \
    set(SESSION_TAIL) | set(CLICK_TAIL) | set(BLOCK2) | {PINNED}
present = sorted(k for k in keys if k in lawish)
absent = sorted(k for k in keys if k not in lawish)
print('law-ish keys present (%d): %s' % (len(present), present))
print('non-law keys       (%d): %s' % (len(absent), absent))
print()

profile = sorted(k for k in keys if k in (set(PROFILE_COMMON) |
                                          set(SESSION_PROFILE) |
                                          set(CLICK_PROFILE)))
tail = sorted(k for k in keys if k in (set(SESSION_TAIL) | set(CLICK_TAIL)))
pinned = [k for k in keys if k == PINNED]
env = sorted(k for k in keys if k in set(BLOCK2))
print('=== derived event claim set ===')
print('  profile (%2d): %s' % (len(profile), profile))
print('  pinned  (%2d): %s' % (len(pinned), pinned))
print('  tail    (%2d): %s' % (len(tail), tail))
print('  envelope(%2d): %s' % (len(env), env))
print('  TOTAL   (%2d keys)' % (len(profile) + len(pinned) + len(tail) + len(env)))
print()
order = profile + pinned + tail + env
pred = ''.join(kv[k] for k in order)
print('predicted desc10 (event):')
print(pred)
print()
print('unpadded len %d B -> padded %d B (%d dwords)'
      % (len(pred), (len(pred) + 3) // 4 * 4, (len(pred) + 3) // 4))
print()
json.dump({'kind': 'event', 'keys': order, 'pred_desc10': pred,
           'keys_unpadded': len(pred), 'source': src},
          open(os.path.join(HERE, 'event_kind.json'), 'w'), indent=1)