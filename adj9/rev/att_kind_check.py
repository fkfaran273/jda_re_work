# att_kind_check.py - cross-check the device's ATTRIBUTION claim set against the
# genuine /attribution request and the slice-99 §8.2 probe results.
#
# gold6_kinds found the third kind: activity_kind="attribution", mapN=31, of which
# 20 are law keys (session law minus hardware_name, initiating_package_name,
# installed_at, os_build, session_count, store_name_from_system, updated_at) plus
# `initiated_by`. The session law has 27 keys, so a session-shaped blob signed for
# an /attribution request is a claim-set mismatch by construction.
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
sys.path.insert(0, HERE)
from desc10_law import desc10_keys

G = json.load(open(os.path.join(DEV, 'gold6.json'), encoding='utf-8'))
GEN = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))

# the attribution map (gold6 idx 2 - the one with activity_kind=attribution)
N = max(len(v) for v in G.values())
att_keys, att_vals = None, None
for i in range(N):
    si = G['sign_input'][i]
    txt = (' '.join(str(x) for x in si) if isinstance(si, (list, tuple)) else str(si))
    if 'map_toString=' not in txt:
        continue
    body = txt.split('map_toString=', 1)[1].strip()
    kv = dict(re.findall(r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*?)(?=, |$|,)',
                         body + ','))
    if kv.get('activity_kind') == 'attribution':
        att_keys = [k for k in re.findall(r'([A-Za-z0-9_]+)=', body)
                    if k not in ('map_order',)]
        att_vals = kv
        break
print('attribution map: %d keys' % len(att_keys))
print('  keys: %s' % sorted(att_keys))
print()

# ---- genuine /attribution QUERY keys ----------------------------------------
qs = GEN['query'].split('?', 1)[1]
q = {k: v[0] for k, v in urllib.parse.parse_qs(qs, keep_blank_values=True).items()}
print('genuine /attribution query: %d keys' % len(q))
print('  keys: %s' % sorted(q))
print()

# ---- the comparison that matters --------------------------------------------
# instrumentation keys the oracle added to the map (not real claims)
INSTR = {'key2_hex', 'key2_len'}
mk = [k for k in att_keys if k not in INSTR]
print('=== attribution map (minus oracle instrumentation) vs the query ===')
print('  map keys not in the query  : %s'
      % sorted(set(mk) - set(q)))   # map-only = claims the wire does not carry
print('  query keys not in the map  : %s'
      % sorted(set(q) - set(mk)))   # wire-only = tolerated / endpoint params
print()

# ---- and the decisive size comparison ---------------------------------------
sess_law = desc10_keys('session', att_vals)
present_law = [k for k in sess_law if k in mk]
absent_law = [k for k in sess_law if k not in mk]
print('=== claim-set sizes (why a session blob cannot verify an attribution req) ===')
print('  session law total          : %d keys' % len(sess_law))
print('  present in attribution map : %d keys' % len(present_law))
print('  ABSENT from attribution map: %d keys -> %s' % (len(absent_law), absent_law))
print('  attribution map keywords not in the session law : %s'
      % sorted(set(mk) - set(sess_law)))
print()
print('  => an /attribution request signed with the SESSION claim set embeds 7 claims')
print('     the request does not carry (installed_at, os_build, hardware_name,')
print('     initiating_package_name, session_count, store_name_from_system,')
print('     updated_at) and omits initiated_by. Claim-set mismatch by construction.')

# ---- §8.2 cross-check --------------------------------------------------------
print()
print('=== slice-99 §8.2 probe cross-check ===')
BEARING = ['initiated_by', 'api_level', 'app_version', 'os_version', 'created_at',
           'device_type', 'environment', 'gps_adid_src', 'tracking_enabled',
           'device_name', 'session_count', 'android_uuid', 'gps_adid']
TOLER = ['ui_mode', 'foreground', 'offline_mode_enabled', 'needs_response_details',
         'attribution_deeplink', 'gps_adid_attempt', 'sent_at']
print('  payload-bearing keys that are in the ATTRIBUTION map : %s'
      % [k for k in BEARING if k in mk])
print('  payload-bearing keys in the SESSION law             : %s'
      % [k for k in BEARING if k in sess_law])
print('  tolerated keys present in the map but NOT in the session law : %s'
      % [k for k in TOLER if k in mk and k not in sess_law])
print('  session-only keys the attribution request would not have : %s'
      % [k for k in ('session_count',) if k not in mk])