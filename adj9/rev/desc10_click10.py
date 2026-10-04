# desc10_click10.py - DEFINITIVE unified desc10 law test:
#   desc10 = block1(activity-kind claim list, A->Z, except adj_signing_id pinned
#            immediately before session_count) + block2(activity_kind client_sdk
#            headers_id native_version, A->Z)
#   SESSION: verify golden 360B from wh4 si[7] map (regression vs law_check).
#   CLICK:   predict 387B from the authoritative toString map (line 286234)
#            and byte-compare vs the captured desc10_runs.json click run.
import json, re

DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
LOG = DEV + r'\adj9_wh4.log'

HEAD = ['adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
        'created_at', 'device_name', 'device_type', 'environment']
TAIL = ['gps_adid', 'gps_adid_src', 'hardware_name', 'installed_at', 'os_build',
        'os_name', 'os_version', 'package_name']
SESSION_ONLY = ['initiating_package_name', 'store_name_from_system']
CLICK_ONLY = ['google_play_instant', 'referrer', 'referrer_api', 'session_length',
              'source', 'subsession_count', 'time_spent']
FIXED = ['adj_signing_id', 'session_count']          # pinned pair, in this order
SESSION_MID = ['tracking_enabled', 'updated_at']
CLICK_MID = ['tracking_enabled', 'updated_at']
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']

def build(val, kind):
    if kind == 'session':
        profile = ['adj_verification', 'android_uuid', 'api_level', 'app_token',
                   'app_version', 'created_at', 'device_name', 'device_type',
                   'environment', 'initiating_package_name', 'gps_adid',
                   'gps_adid_src', 'hardware_name', 'installed_at', 'os_build',
                   'os_name', 'os_version', 'package_name']
        sess = ['session_count', 'store_name_from_system', 'tracking_enabled',
                'updated_at']
    else:
        profile = ['adj_verification', 'android_uuid', 'api_level', 'app_token',
                   'app_version', 'created_at', 'device_name', 'device_type',
                   'environment', 'google_play_instant', 'gps_adid',
                   'gps_adid_src', 'hardware_name', 'installed_at', 'os_build',
                   'os_name', 'os_version', 'package_name', 'referrer',
                   'referrer_api']
        sess = ['session_count', 'session_length', 'source', 'subsession_count',
                'time_spent', 'tracking_enabled', 'updated_at']
    keys = sorted(profile) + ['adj_signing_id'] + sorted(sess) + BLOCK2
    missing = [k for k in keys if k not in val or val[k] == '']
    if missing:
        raise SystemExit('missing values: %s' % missing)
    return ''.join(val[k] for k in keys), keys

# ---------- SESSION (regression): wh4 si[7] ----------
W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))
D = json.load(open(REV + r'\fin_descs.json', encoding='utf-8'))
d10 = bytes.fromhex([d for d in D['descs'] if d['build_idx'] == 10][0]['data_hex']).decode('latin1')
si = W['sign_inputs'][W['golden_sign_input_idx']]
sval = {}
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        sval[k] = v
pred, keys = build(sval, 'session')
print('SESSION: predicted %d B vs golden %d B -> %s' % (
    len(pred), len(d10), 'BYTE-EXACT' if pred == d10 else 'MISMATCH @%d' %
    next(i for i in range(min(len(pred), len(d10))) if pred[i] != d10[i])))

# ---------- CLICK: authoritative map from toString line 286234 ----------
with open(LOG, encoding='utf-8', errors='replace') as f:
    for ln, line in enumerate(f, 1):
        if ln == 286234:
            tostr_line = line.strip()
            break
m = re.search(r'\{(.*)\}', tostr_line)
cval = dict(re.findall(r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*), ?', m.group(1) + ','))
# signer adds 3 constants after map get: adj_signing_id(nSign arg), headers_id,
# native_version (both header-only; values confirmed identical across si[0..7])
cval.setdefault('adj_signing_id', '1500000')
cval.setdefault('headers_id', '10')
cval.setdefault('native_version', '5.0.0')
click = json.load(open(REV + r'\desc10_runs.json', encoding='utf-8'))['click']
predc, ckeys = build(cval, 'click')
print('CLICK:   predicted %d B vs captured %d B -> %s' % (
    len(predc), len(click), 'BYTE-EXACT' if predc == click else 'MISMATCH @%d' %
    next((i for i in range(min(len(predc), len(click))) if predc[i] != click[i]), -1)))
print()
if predc == click and pred == d10:
    print('*** UNIFIED desc10 LAW PROVEN FOR BOTH ACTIVITY KINDS ***')
print('click key order emitted:')
off = 0
for k in ckeys:
    print('  %4d %3d %-26s %r' % (off, len(cval[k]), k, cval[k][:44]))
    off += len(cval[k])
