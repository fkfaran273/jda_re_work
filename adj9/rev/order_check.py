# checker for the desc10 field-order hypothesis (monotonic subset of map_order)
import json
C = json.load(open('corpus.json'))
mp = C['sign_inputs'][0]
order = mp['map_order']
pairs = mp['map_toString']
items = [p.split('=', 1) for p in pairs.lstrip('{').rstrip('}').split(', ')]
val_by_key = dict(items)
D = json.load(open('fin_descs.json'))
d10 = bytes.fromhex([d for d in D['descs'] if d['build_idx'] == 10][0]['data_hex']).decode('latin1')
obs = [(0,'adj_verification',28),(28,'android_uuid',36),(64,'api_level',2),(66,'app_token',12),
       (78,'app_version',6),(84,'created_at',29),(113,'device_name',8),(121,'device_type',5),
       (126,'environment',10),(136,'gps_adid',36),(172,'gps_adid_src',7),(179,'hardware_name',14),
       (193,'store#1',19),(212,'installed_at',29),(241,'os_build',14),(255,'os_name',7),
       (262,'os_version',2),(264,'package_name',13),(277,'adj_signing_id',7),(284,'?1a',1),
       (285,'store#2',19),(304,'?1b',1),(305,'updated_at',29),(334,'activity_kind',7),
       (341,'client_sdk',12),(353,'headers_id',2),(355,'native_version',5)]
bad = 0
for st, k, ln in obs:
    seg = d10[st:st+ln]
    if k in val_by_key and seg != val_by_key[k]:
        print('MISMATCH', k, repr(seg), 'vs', repr(val_by_key[k])); bad += 1
print('known-key mismatches:', bad)
idx = {k: i for i, k in enumerate(order)}
prev = -1; mono = True
for st, k, ln in obs:
    i = idx.get(k)
    mark = ''
    if i is not None:
        if i < prev: mark = ' <-- BREAKS MONOTONIC'; mono = False
        prev = i
    print('%4d %-18s idx=%s%s' % (st, k, i, mark))
print('monotonic subset of map_order:', mono)
ones = [k for k, v in items if v == '1']
print("fields with value '1':", ones)
vend = [k for k, v in items if v == 'com.android.vending']
print('fields with vending value:', vend)
used = {k for _, k, _ in obs if k in val_by_key}
missing = [k for k in order if k not in used]
print('map fields not in desc10 (%d):' % len(missing))
print(missing)
