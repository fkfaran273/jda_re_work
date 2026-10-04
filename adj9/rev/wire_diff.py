# wire_diff.py - EXACTLY what our crafted requests send vs what the APP sends.
#
# The genuine /attribution query (rev/fresh_genuine.json, captured from the real
# device) has 22 keys, and the device's own attribution map has 29. The 7-key
# difference is the header-only set:
#     activity_kind, adj_signing_id, adj_verification, algorithm,
#     client_sdk, headers_id, native_version
# => the app NEVER sends those 7 on the wire; they ride in the Authorization header.
#
# Our crafted senders have been posting the WHOLE map plus extras. This script
# prints that difference for session and click, which is the first concrete
# candidate for "something we are missing".
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')

HDR_ONLY = {'activity_kind', 'adj_signing_id', 'adj_verification', 'algorithm',
            'client_sdk', 'headers_id', 'native_version'}
EXTRA_NEVER_SENT = {'ask_in', 'key2_hex', 'key2_len', 'map_order'}
# resolved from slice 99 §8.2: the server TOLERATES these but they are not claims
TOLERATED = {'ui_mode', 'foreground', 'offline_mode_enabled',
             'needs_response_details', 'attribution_deeplink', 'gps_adid_attempt',
             'sent_at'}

# ---- the app's genuine wire sets -------------------------------------------
GEN = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))
att_wire = set(urllib.parse.parse_qs(GEN['query'].split('?', 1)[1],
                                     keep_blank_values=True))
print('=== the app\'s genuine /attribution WIRE param set (%d) ===' % len(att_wire))
print('  %s' % sorted(att_wire))
print()

W = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
si = W['sign_inputs'][W['golden_sign_input_idx']]
smap = {}
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        smap[k] = v
print('=== the app\'s SESSION map (signed set): %d keys ===' % len(smap))
sess_wire = sorted(set(smap) - HDR_ONLY)
print('  inferred WIRE set = map - 7 header fields = %d keys' % len(sess_wire))
print('  %s' % sess_wire)
print('  (SAZ measured the real session wire at 43 params -> MATCH: %s)'
      % (len(sess_wire) == 43))
print()

# ---- what our crafted sender posted ----------------------------------------
ours = set(smap) | {'ask_in'}
print('=== our crafted /session POST ==')
print('  params sent: %d' % len(ours))
print('  params the APP never sends : %s' % sorted(ours - set(sess_wire)))
print('  params the app sends that WE omit : %s'
      % sorted(set(sess_wire) - ours))
print()

# ---- click side ------------------------------------------------------------
G6 = json.load(open(os.path.join(DEV, 'gold6.json'), encoding='utf-8'))
N = max(len(v) for v in G6.values())
cmap = None
for i in range(N):
    v = G6['sign_input'][i]
    txt = (' '.join(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v))
    if 'map_toString=' in txt and 'referrer' in txt:
        body = txt.split('map_toString=', 1)[1].strip()
        cmap = dict(re.findall(r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*?)(?=, |$|,)',
                               body + ','))
        break
if cmap:
    cwire = sorted(set(cmap) - HDR_ONLY)
    print('=== the app\'s CLICK map: %d keys -> wire %d keys ==='
          % (len(cmap), len(cwire)))
    print('  wire: %s' % cwire)
    print('  (SAZ measured the real click wire at 47 params -> %s)'
          % ('MATCH' if len(cwire) == 47 else
             'differs by %d' % abs(len(cwire) - 47)))
    print()
    print('  our crafted /sdk_click sent the whole map (%d) => %d extras: %s'
          % (len(cmap), len(set(cmap) - set(cwire)), sorted(set(cmap) - set(cwire))))

# ---- the concrete fix ------------------------------------------------------
print()
print('=== FIX to test ===')
print('  * sign over the FULL law map (unchanged - the blob needs it)')
print('  * POST only the wire params: map MINUS %s' % sorted(HDR_ONLY))
print('  * never send: %s' % sorted(EXTRA_NEVER_SENT))
print('  * optionally include the tolerated keys only if the app does')
json.dump({'header_only': sorted(HDR_ONLY),
           'session_wire': sess_wire,
           'attribution_wire': sorted(att_wire),
           'click_wire': cwire if cmap else None},
          open(os.path.join(HERE, 'wire_sets.json'), 'w'), indent=1)
print('\nsaved wire_sets.json')