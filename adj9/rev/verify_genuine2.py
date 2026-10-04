# verify_genuine2.py - reproduce the GENUINE device /attribution signature.
# The desc10 law implements the 'session' record (a fixed 360-B layout). An
# attribution request omits several session fields, so they are filled from the
# device's own constants (rev/minted4.json sigmap + the SDK's fixed header
# values) before the law is applied.
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from header_gen import make_header

G = json.load(open(os.path.join(HERE, 'fresh_genuine.json'), encoding='utf-8'))
qs = G['query'].split('?', 1)[1]
val = {k: v[0] for k, v in urllib.parse.parse_qs(qs, keep_blank_values=True).items()}
blob = bytes.fromhex(G['blob_hex'])
second = 1789474915

FILL = {
    'hardware_name': 'S2SE32.28-28-4',
    'os_build': 'S2SE32.28-28-4',
    'store_name_from_system': 'com.android.vending',
    'initiating_package_name': 'com.android.vending',
    'installed_at': '2026-09-14T17:52:12.431Z+0530',
    'updated_at': '2026-09-14T17:52:12.431Z+0530',
    'session_count': '1',
    'subsession_count': '0',
    'session_length': '0',
    'time_spent': '0',
    'adj_signing_id': '1500000',
    'adj_verification': 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
    'device_manufacturer': 'motorola',
    'language': 'tr',
    'cpu_type': 'arm64-v8a',
    'display_width': '1080',
    'display_height': '2237',
    'screen_size': 'normal',
    'screen_format': 'long',
    'screen_density': 'high',
    'connectivity_type': '1',
    'wait_total': '0.0',
    'wait_time': '0.0',
    'retry_count': '0',
    'first_error': '0',
    'last_error': '0',
    'enqueue_size': '0',
    'activity_kind': 'session',
    'client_sdk': 'android5.7.0',
    'headers_id': '10',
    'native_version': '5.0.0',
}
merged = dict(FILL)
merged.update(val)

print('genuine blob %d B  second=%d' % (len(blob), second))
print('map keys after fill: %d' % len(merged))
for kind in ('session', 'click'):
    try:
        st, got, _ = F.make_signature_map(merged, kind=kind, second=second)
    except Exception as e:
        print('kind=%-9s -> %s: %s' % (kind, type(e).__name__, str(e)[:170]))
        continue
    same = got == blob
    diff = [i for i in range(48)
            if got[i * 4:i * 4 + 4] != blob[i * 4:i * 4 + 4]]
    print('kind=%-9s status=%-11s law=%-3s equal=%-5s differing=%d/48 %s'
          % (kind, st, 'OK' if got[:16] == make_header(second) else 'BAD', same,
             len(diff), diff[:10]))
    if same:
        print('\n*** BYTE-EXACT REPRODUCTION OF THE GENUINE DEVICE SIGNATURE ***')
        break