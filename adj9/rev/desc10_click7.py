# desc10_click7.py - final click-order resolution: labeled DP over the click record's
# own recovered map (25 keys) to identify which key emits '0', '10', '10' in the 136-368
# zone; then prove the 3-run alphabetical law for CLICK byte-exactly.
import json

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
click = json.load(open(REV + r'\desc10_runs.json', encoding='utf-8'))['click']

# golden-device click map (desc10_click6 recovered + click-only keys not fetched)
V = {
 'adj_verification': 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
 'android_uuid': 'd773f47f-fc0e-4994-9cf7-7c3cf5bb6368',
 'api_level': '31', 'app_token': 'jut9tib0eeps', 'app_version': '3.13.9',
 'created_at': '2026-09-12T21:15:11.762Z+0200', 'device_name': 'moto g42',
 'device_type': 'phone', 'environment': 'production', 'foreground': '0',
 'gps_adid': 'f476b3d4-e0b1-4707-bc43-6153d17f7f8c', 'gps_adid_src': 'service',
 'hardware_name': 'S2SE32.28-28-4', 'installed_at': '2026-09-08T12:20:49.782Z+0200',
 'os_build': 'S2SE32.28-28-4', 'os_name': 'android', 'os_version': '12',
 'package_name': 'com.penti.app',
 'referrer': 'utm_source=google-play&utm_medium=organic', 'referrer_api': 'google',
 'source': 'install_referrer', 'session_count': '1', 'tracking_enabled': '1',
 'updated_at': '2026-09-10T07:26:18.015Z+0200', 'activity_kind': 'click',
 'client_sdk': 'android5.7.0', 'adj_signing_id': '1500000', 'headers_id': '10',
 'native_version': '5.0.0',
 'initiating_package_name': 'com.android.vending',   # not fetched, unknown value
 'store_name_from_system': 'com.android.vending',    # not fetched, unknown value
 'offline_mode_enabled': '0',
}
n = len(click)
INF = 10 ** 9
dp = [INF] * (n + 1); back = [None] * (n + 1); dp[0] = 0
for i in range(n):
    if dp[i] >= INF:
        continue
    for k, v in V.items():
        if v and click.startswith(v, i):
            j = i + len(v)
            if dp[i] + 1 < dp[j]:
                dp[j] = dp[i] + 1; back[j] = (i, k)
if dp[n] >= INF:
    print('UNREACHABLE'); raise SystemExit
seq = []
j = n
while j > 0:
    i, k = back[j]; seq.append(k); j = i
seq.reverse()
off = 0
print('=== labeled click sequence (%d tokens) ===' % len(seq))
for k in seq:
    v = V[k]
    print('  %4d %3d %-26s %r' % (off, len(v), k, v))
    off += len(v)
print('covered:', off, '/', n)
