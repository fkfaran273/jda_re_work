# order_check2 - correct pairing (golden desc10 <-> its own corpus signing) + true monotonic test
import json
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
C = json.load(open(REV + r'\corpus.json', encoding='utf-8'))
D = json.load(open(REV + r'\fin_descs.json', encoding='utf-8'))
sigs = C['sign_inputs']
gi = None
for i, mp in enumerate(sigs):
    s = json.dumps(mp)
    if '2026-09-12T21:15:11.678Z' in s and 'd773f47f' in s:
        gi = i
        break
print('golden sign_input index:', gi, 'of', len(sigs))
mp = sigs[gi if gi is not None else 0]
fields = []
for part in mp['map_order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        fields.append((k, v))
order = [k for k, _ in fields]
val_by_key = dict(fields)
print('map fields:', len(fields))
d10 = bytes.fromhex([d for d in D['descs'] if d['build_idx'] == 10][0]['data_hex']).decode('latin1')
print('desc10 len:', len(d10))
obs = [(0,'adj_verification',28),(28,'android_uuid',36),(64,'api_level',2),(66,'app_token',12),
       (78,'app_version',6),(84,'created_at',29),(113,'device_name',8),(121,'device_type',5),
       (126,'environment',10),(136,'gps_adid',36),(172,'gps_adid_src',7),(179,'hardware_name',14),
       (193,'store#1',19),(212,'installed_at',29),(241,'os_build',14),(255,'os_name',7),
       (262,'os_version',2),(264,'package_name',13),(277,'adj_signing_id',7),(284,'?1a',1),
       (285,'store#2',19),(304,'?1b',1),(305,'updated_at',29),(334,'activity_kind',7),
       (341,'client_sdk',12),(353,'headers_id',2),(355,'native_version',5)]
bad = 0
for st, k, ln in obs:
    if k in val_by_key and d10[st:st+ln] != val_by_key[k]:
        print('MISMATCH', k, repr(d10[st:st+ln]), 'vs', repr(val_by_key[k]))
        bad += 1
print('value mismatches:', bad)
print('store#1 =', repr(d10[193:212]), '| store#2 =', repr(d10[285:304]))
print('  map: store_name_from_system =', repr(val_by_key.get('store_name_from_system')),
      '| initiating_package_name =', repr(val_by_key.get('initiating_package_name')))
idx = {k: i for i, k in enumerate(order)}
prev = -1
mono = True
for st, k, ln in obs:
    i = idx.get(k)
    mk = ''
    if i is not None:
        if i < prev:
            mk = '  <BREAK'
            mono = False
        prev = i
    print('%4d %-22s idx=%s%s' % (st, k, i, mk))
print('monotonic subset of map insertion order:', mono)
ones = [k for k, v in fields if v == '1']
print('1-valued fields:', ones)
alpha = sorted(k for k, _ in fields)
print('desc10 known keys in alpha order?', [k for _, k, _ in obs if k in val_by_key] ==
      [k for k in alpha if k in {kk for _, kk, _ in obs}])
