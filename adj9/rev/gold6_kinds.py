# gold6_kinds.py - characterize the three activity kinds captured in gold6.json.
#
# gold6_audit found: 52-key session maps (27/27 law keys), 60-key CLICK maps
# (32/32 law keys), and 31-key maps that miss exactly
# hardware_name / initiating_package_name / installed_at / os_build /
# session_count / store_name_from_system / updated_at. desc10_law says the third
# kind is "pending a capture" - this identifies it and its claim set.
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
sys.path.insert(0, HERE)
from desc10_law import (desc10_keys, PROFILE_COMMON, SESSION_PROFILE,
                        SESSION_TAIL, CLICK_PROFILE, CLICK_TAIL, BLOCK2, PINNED)

G = json.load(open(os.path.join(DEV, 'gold6.json'), encoding='utf-8'))
N = max(len(v) for v in G.values())


def signing(i):
    out = {}
    for k, v in G.items():
        if isinstance(v, list) and i < len(v):
            item = v[i]
            out[k] = (' '.join(str(x) for x in item)
                      if isinstance(item, (list, tuple)) else str(item))
    return out


def kvmap(txt):
    body = txt.split('map_toString=', 1)[1].strip()
    return dict(re.findall(r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*?)(?=, |$|,)',
                           body + ',')), body


print('%-4s %-9s %-6s %-8s %s' % ('idx', 'kind', 'mapN', 'act_kind', 'signature of the map'))
recs = []
for i in range(N):
    s = signing(i)
    si = s.get('sign_input', '')
    if 'map_toString=' not in si:
        continue
    kv, body = kvmap(si)
    keys = [k for k in re.findall(r'([A-Za-z0-9_]+)=', body) if k not in ('map_order',)]
    kind = 'click' if ('referrer' in keys or 'google_play_instant' in keys) else 'session'
    ak = kv.get('activity_kind', '?')
    print('%-4d %-9s %-6d %-8s %s' % (i, kind, len(keys), ak,
                                      'has_install=%s has_session_tail=%s has_click=%s'
                                      % ('installed_at' in keys,
                                         'session_count' in keys,
                                         'referrer' in keys)))
    recs.append((i, kind, keys, kv))

print()
print('=== per-kind claim sets (present vs the law) ===')
seen = set()
for i, kind, keys, kv in recs:
    sig = (kind, len(keys))
    law = set(desc10_keys(kind, dict.fromkeys(keys, 'x')))
    missing = sorted(law - set(keys))
    extra = sorted(set(keys) - law)
    tag = 'NEW KIND' if (kind, tuple(missing)) not in seen else 'repeat'
    seen.add((kind, tuple(missing)))
    print('  idx %-3d kind=%-8s mapN=%-3d law=%d  %s' % (i, kind, len(keys), len(law), tag))
    if missing:
        print('       law keys ABSENT from the map: %s' % missing)
    print('       map keys not in the law      : %s' % extra)

print()
print('=== hypothesis: the 31-key kind is activity_kind == "event" ===')
for i, kind, keys, kv in recs:
    if len(keys) < 40:
        print('  idx %d activity_kind=%r' % (i, kv.get('activity_kind')))
        print('       keys: %s' % sorted(keys))
        print('       event desc10 (law restricted to present keys) would be %d keys'
              % len([k for k in desc10_keys('session', kv) if k in keys]))