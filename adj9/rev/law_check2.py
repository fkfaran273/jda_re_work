# law_check2.py - verify the native claim-fetch unit is FIXED across ALL 8 signings
# unit candidates: 24 keys (no adj_signing_id) and 25 keys (with it, sorted first)
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
            m2 = re.match(r'text: th=\S+ this=\d+ key=(\S+) val=(.*)', line.rstrip('\r\n'))
            if m2 and m2.group(1) in CLAIMS:
                gets.append((ln, m2.group(1), m2.group(2)))
        elif cur == 'nsign':
            m2 = re.match(r'hex=([0-9a-f]+)', line)
            if m2:
                nsigns.append((ln, m2.group(1)))

A22 = sorted(['adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
              'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
              'gps_adid_src', 'hardware_name', 'initiating_package_name', 'installed_at',
              'os_build', 'os_name', 'os_version', 'package_name', 'session_count',
              'store_name_from_system', 'tracking_enabled', 'updated_at'])
UNIT24 = A22 + ['activity_kind', 'client_sdk']
UNIT25 = ['adj_signing_id'] + UNIT24
print('UNIT25 (25):', UNIT25)

bounds = [b[0] for b in nsigns] + [10 ** 12]
for i, (ln0, (g_ln, g_hex)) in enumerate(zip([0] + bounds[:-1], nsigns)):
    burst = [(ln, k, v) for ln, k, v in gets if ln0 < ln <= g_ln]
    ks = [k for _, k, _ in burst]
    out = []
    for name, U in (('24', UNIT24), ('25', UNIT25)):
        n, j = 0, 0
        while j <= len(ks) - len(U):
            if ks[j:j + len(U)] == U:
                n += 1
                j += len(U)
            else:
                j += 1
        out.append('u%s=%d' % (name, n))
    # per-signing unique-in-sequence of the LAST unit-sized window
    for name, U in (('25', UNIT25), ('24', UNIT24)):
        if len(ks) >= len(U):
            win = ks[-len(U):]
            uniq = []
            for k in win:
                if not uniq or uniq[-1] != k:
                    uniq.append(k)
            if uniq == U:
                out.append('last-window==u%s' % name)
                break
    print('signing %d blob=%s burst=%4d gets | %s' % (i, g_hex[:8], len(burst), ' '.join(out)))

