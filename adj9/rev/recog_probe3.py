# recog_probe3.py - MAP THE SERVER'S VERIFIED PAYLOAD: change ONE query param at a
# time on the byte-exact genuine blob. 400 = still recognized (param NOT in the
# signed payload); 200+Organic = payload-bearing param.
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_full_chain as F

G = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))
GEN = bytes.fromhex(G['blob_hex'])
Q = {k: v[0] for k, v in urllib.parse.parse_qs(
    urllib.parse.urlsplit(G['query']).query).items()}
F.USE_DEVICE = True
F.NO_SIGN = False
print('genuine query: %s' % json.dumps(Q, indent=1)[:600])

CASES = [
    ('CONTROL verbatim', {}),
    ('initiated_by=backend->sdk', {'initiated_by': 'sdk'}),
    ('gps_adid_attempt=1->2', {'gps_adid_attempt': '2'}),
    ('api_level=31->30', {'api_level': '30'}),
    ('app_version->3.13.8', {'app_version': '3.13.8'}),
    ('os_version=12->11', {'os_version': '11'}),
    ('created_at +1ms', {'created_at': '2026-09-15T17:51:54.999Z+0530'}),
    ('sent_at +1ms', {'sent_at': '2026-09-15T17:51:54.999Z+0530'}),
    ('device_type=phone->tablet', {'device_type': 'tablet'}),
    ('foreground=1->0', {'foreground': '0'}),
    ('offline_mode_enabled=0->1', {'offline_mode_enabled': '1'}),
    ('needs_response_details=1->0', {'needs_response_details': '0'}),
    ('attribution_deeplink=1->0', {'attribution_deeplink': '0'}),
    ('environment->sandbox', {'environment': 'sandbox'}),
    ('ui_mode=1->0', {'ui_mode': '0'}),
    ('gps_adid_src=service->tracker', {'gps_adid_src': 'tracker'}),
    ('tracking_enabled=1->0', {'tracking_enabled': '0'}),
    ('CONTROL verbatim (repeat)', {}),
]
res = []
for label, over in CASES:
    params = dict(Q)
    params.update(over)
    code, body = F.send_device('https://app.adjust.com/attribution', params, GEN,
                               method='GET')
    rec = 'RECOGNIZED(400)' if code == 400 else (
        'not-recognized(200)' if code == 200 else 'HTTP %s' % code)
    print('%-32s -> %-20s %s' % (label, rec,
                                 body.strip().replace('\r\n', '')[:90]), flush=True)
    res.append({'label': label, 'http': code, 'verdict': rec})
    time.sleep(2)
json.dump(res, open(os.path.join(HERE, 'recog_probe3_result.json'), 'w'), indent=1)

print()
print('=== SERVER-SIDE VERIFIED PAYLOAD MAP ===')
payload = [r['label'] for r in res if r['http'] == 200]
notp = [r['label'] for r in res if r['http'] == 400]
print('payload-bearing (change breaks verification):')
for x in payload:
    print('   %s' % x)
print('NOT payload (change tolerated -> recognized):')
for x in notp:
    print('   %s' % x)