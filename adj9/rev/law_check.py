# law_check.py - THE desc10 law test: reconstruct the golden 360B desc10 from its
# own map (wh4 sign_input[7]) using the three-alphabetical-runs law; byte-compare
# vs fin_descs.json desc10.
import json

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))
D = json.load(open(REV + r'\fin_descs.json', encoding='utf-8'))
d10 = bytes.fromhex([d for d in D['descs'] if d['build_idx'] == 10][0]['data_hex']).decode('latin1')

si = W['sign_inputs'][W['golden_sign_input_idx']]
fields = []
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        fields.append((k, v))
val = dict(fields)
print('golden map fields:', len(fields), '| desc10 len:', len(d10))

G1 = ['adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
      'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
      'gps_adid_src', 'hardware_name', 'initiating_package_name', 'installed_at',
      'os_build', 'os_name', 'os_version', 'package_name']
G2 = ['adj_signing_id', 'session_count', 'store_name_from_system', 'tracking_enabled',
      'updated_at']
G3 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']

# run-internal alphabetical sanity
for nm, g in (('G1', G1), ('G2', G2), ('G3', G3)):
    print('%s alphabetical: %s' % (nm, g == sorted(g)))

missing = [k for g in (G1, G2, G3) for k in g if k not in val]
print('keys missing from map:', missing)
pred = ''.join(val[k] for g in (G1, G2, G3) for k in sorted(g))
print('predicted len:', len(pred), '| target len:', len(d10))
if pred == d10:
    print('*** BYTE-EXACT: desc10 law PROVEN (3 alphabetical runs) ***')
else:
    p = 0
    while p < min(len(pred), len(d10)) and pred[p] == d10[p]:
        p += 1
    print('first divergence at byte', p)
    print('  pred:', repr(pred[max(0, p - 30):p + 40]))
    print('  d10 :', repr(d10[max(0, p - 30):p + 40]))

# offsets table for the memory/slice record
off = 0
print('=== resolved byte map ===')
for gname, g in (('G1', G1), ('G2', G2), ('G3', G3)):
    for k in sorted(g):
        v = val[k]
        print('%4d %3d %-26s %r' % (off, len(v), k, v[:40]))
        off += len(v)
print('total:', off)

# cross-check: (a) d10 values match map at every predicted slot; (b) full coverage
ok = True
off = 0
for g in (G1, G2, G3):
    for k in sorted(g):
        v = val[k]
        if d10[off:off + len(v)] != v:
            print('SLOT MISMATCH', k, off); ok = False
        off += len(v)
print('per-slot verification:', 'PASS' if ok else 'FAIL')
