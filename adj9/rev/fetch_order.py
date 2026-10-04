# fetch_order.py - native claim-fetch order from adj9_wh4.log mapget blocks
# (block format: ###ADJ9_BEGIN type=mapget / text: th=... this=... key=K val=V)
import json, re

LOG = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device\adj9_wh4.log'
CLAIMS = set('''adj_verification android_uuid api_level app_token app_version created_at device_name
device_type environment gps_adid gps_adid_src hardware_name installed_at os_build os_name os_version
package_name adj_signing_id updated_at activity_kind client_sdk headers_id native_version
store_name_from_system initiating_package_name session_count tracking_enabled gps_adid_attempt foreground
connectivity_type needs_response_details attribution_deeplink ui_mode payload_timer wait_time wait_total
retry_count first_error last_error queue_size sent_at device_manufacturer display_width display_height
screen_density screen_format screen_size language cpu_type offline_mode_enabled android_id fire_adid'''.split())

nsigns, gets = [], []
with open(LOG, encoding='utf-8', errors='replace') as f:
    cur = None
    for ln, line in enumerate(f, 1):
        m = re.match(r'###ADJ9_BEGIN type=(\w+)', line)
        if m:
            cur = m.group(1)
            continue
        if cur == 'mapget':
            m2 = re.match(r'text: th=\S+ this=(\d+) key=(\S+) val=(.*)', line.rstrip('\r\n'))
            if m2 and m2.group(2) in CLAIMS:
                gets.append((ln, m2.group(2), m2.group(3)))
        elif cur == 'nsign':
            m2 = re.match(r'hex=([0-9a-f]+)', line)
            if m2:
                nsigns.append((ln, m2.group(1)))
print('nsign records:', len(nsigns), '| claim-name mapgets:', len(gets))

# golden = last signing's fetch burst (nsign[7]=5595c3c4; its mapgets precede it)
g_ln, g_hex = nsigns[-1]
prev_ln = nsigns[-2][0] if len(nsigns) > 1 else 0
burst = [(ln, k, v) for ln, k, v in gets if prev_ln < ln <= g_ln]
print('golden burst %s: %d claim mapgets between lines %d..%d' % (g_hex[:8], len(burst), prev_ln, g_ln))

# verify values against the golden map
W = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\wh4_records.json', encoding='utf-8'))
si = W['sign_inputs'][W['golden_sign_input_idx']]
fields = []
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        fields.append((k, v))
val = dict(fields)

seq = []
for ln, k, v in burst:
    if seq and seq[-1] == k:
        continue
    okv = 'OK' if val.get(k) == v else ('(val! %r)' % v[:24] if k in val else '(NOT-IN-MAP)')
    seq.append(k)
    print('  %6d %-26s %s' % (ln, k, okv))
print('unique-in-sequence fetch order (%d):' % len(seq))
print(seq)

D = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\fin_descs.json', encoding='utf-8'))
d10 = bytes.fromhex([d for d in D['descs'] if d['build_idx'] == 10][0]['data_hex']).decode('latin1')
OBS = ['adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version', 'created_at',
       'device_name', 'device_type', 'environment', 'gps_adid', 'gps_adid_src', 'hardware_name',
       'VEND1', 'installed_at', 'os_build', 'os_name', 'os_version', 'package_name',
       'adj_signing_id', 'ONE1', 'VEND2', 'ONE2', 'updated_at', 'activity_kind', 'client_sdk',
       'headers_id', 'native_version']
print('desc10 emission order (%d):' % len(OBS))
print(OBS)
known = [k for k in OBS if k in val]
idx = {k: i for i, k in enumerate(seq)}
ii = [idx[k] for k in known if k in idx]
print('desc10 known keys in fetch-order positions:', ii)
print('monotonic vs fetch order:', all(ii[i] < ii[i + 1] for i in range(len(ii) - 1)))

