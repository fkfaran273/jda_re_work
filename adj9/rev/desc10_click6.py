# desc10_click6.py - the golden-device click's OWN map: unique values from the last
# click mapget burst (wh4 lines ~286400-286650, map this=244449033), then predict the
# 387B click desc10 and byte-compare vs desc10_runs.json.
import json, re

DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
LOG = DEV + r'\adj9_wh4.log'

CLAIMS = set('''adj_verification android_uuid api_level app_token app_version created_at device_name
device_type environment gps_adid gps_adid_src hardware_name installed_at os_build os_name os_version
package_name adj_signing_id updated_at activity_kind client_sdk headers_id native_version
store_name_from_system initiating_package_name session_count tracking_enabled referrer referrer_api
source foreground offline_mode_enabled'''.split())

vals = {}   # first occurrence per key in the burst window
with open(LOG, encoding='utf-8', errors='replace') as f:
    for ln, line in enumerate(f, 1):
        if ln < 286400 or ln > 286650:
            continue
        m = re.match(r'text: th=\S+ this=(\d+) key=(\S+) val=(.*)', line.rstrip('\r\n'))
        if m and m.group(2) in CLAIMS:
            k, v = m.group(2), m.group(3)
            if k not in vals:
                vals[k] = v
print('=== golden-device click map: %d keys ===' % len(vals))
for k in sorted(vals):
    print('  %-26s %r' % (k, vals[k]))

R = json.load(open(REV + r'\desc10_runs.json', encoding='utf-8'))
click = R['click']
print()
print('target len:', len(click))

# candidate laws:
def build(order_groups):
    out = ''
    for g in order_groups:
        for k in sorted(g):
            if k in vals and vals[k] != '':
                out += vals[k]
    return out

G1 = ['adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
      'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
      'gps_adid_src', 'hardware_name', 'installed_at', 'os_build', 'os_name',
      'os_version', 'package_name']          # click variant: no initiating_package_name
# r..u region candidates in map order:
RU = ['referrer', 'referrer_api', 'adj_signing_id', 'session_count', 'source',
      'tracking_enabled', 'updated_at']
G3 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']

pred = build([G1, RU, G3])
print('pred len:', len(pred))
if pred == click:
    print('*** BYTE-EXACT: click desc10 law PROVEN ***')
else:
    p = 0
    while p < min(len(pred), len(click)) and pred[p] == click[p]:
        p += 1
    print('first divergence at byte', p)
    print('  pred:', repr(pred[max(0, p - 40):p + 50]))
    print('  clk :', repr(click[max(0, p - 40):p + 50]))
