# pack3.py - packing law v3 on golden S1/S2 maps (concat of fixed subset, key-less)
import json, struct, sys
HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
sys.path.insert(0, HERE)
D = json.load(open(HERE + '/fin_descs.json'))
by = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex'])) for d in D['descs']}
T10 = by[10][1]

ORDER = ['adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
         'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
         'gps_adid_src', 'hardware_name', 'initiating_package_name', 'installed_at',
         'os_build', 'os_name', 'os_version', 'package_name', 'adj_signing_id',
         'session_count', 'store_name_from_system', 'tracking_enabled', 'updated_at']

G = json.load(open(HERE + '/golden_saz.json'))
for label, key in (('S1', 's1'), ('S2', 's2')):
    p = dict(G[key]['params'])
    p.setdefault('client_sdk', 'android5.7.0')
    p.setdefault('adj_verification', 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI')
    p.setdefault('adj_signing_id', '1500000')
    p.setdefault('native_version', '5.0.0')
    p.setdefault('headers_id', '10')
    p.setdefault('algorithm', 'adj9')
    missing = [k for k in ORDER if k not in p]
    packed = ''.join(str(p[k]) for k in ORDER if k in p) + 'sessionandroid5.7.0105.0.0'
    packed = packed.encode()
    print(f'--- {label}: missing={missing}')
    print('  packed len:', len(packed), ' T10 len:', len(T10))
    if packed == T10:
        print('  *** EXACT MATCH ***')
    else:
        n = min(len(packed), len(T10))
        j = next((q for q in range(n) if packed[q] != T10[q]), n)
        print('  first diff @', j)
        print('  packed:', packed[max(0, j-60):j+80])
        print('  templ :', T10[max(0, j-60):j+80])

