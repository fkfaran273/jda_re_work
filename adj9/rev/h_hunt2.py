# h_hunt2.py - H4: desc10 emission order = Java HashMap bucket-iteration order
import json, sys
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9')
from canonical import JavaHashMap, table_size_for, java_string_hash_code, spread
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
C = json.load(open(REV + r'\corpus.json', encoding='utf-8'))
# 50-field map (golden signing's full canonical, from any corpus entry: identical static content)
mp = C['sign_inputs'][0]
fields = []
for part in mp['map_order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        fields.append((k, v))
print('map fields:', len(fields))

# observed desc10 emission order (27 slots; ?1a/?1b = unknown '1'-valued fields,
# store#1/#2 = the two vending-valued fields)
OBS = ['adj_verification','android_uuid','api_level','app_token','app_version','created_at',
       'device_name','device_type','environment','gps_adid','gps_adid_src','hardware_name',
       'VEND1','installed_at','os_build','os_name','os_version','package_name',
       'adj_signing_id','ONE1','VEND2','ONE2','updated_at','activity_kind','client_sdk',
       'headers_id','native_version']

ONES = ['gps_adid_attempt','foreground','connectivity_type','needs_response_details',
        'attribution_deeplink','session_count','ui_mode','tracking_enabled']
VENDS = ['store_name_from_system','initiating_package_name']

def rel_order_match(model_keys, obs):
    # obs entries map to concrete keys; check the concrete sequence is a subsequence
    # of model order (relative order preserved)
    idx = {k: i for i, k in enumerate(model_keys)}
    seq = []
    for o in obs:
        cands = CAND[o] if o in CAND else [o]
        ii = [idx[c] for c in cands if c in idx]
        if not ii:
            return False, o
        seq.append(min(ii))
    return all(seq[i] < seq[i+1] for i in range(len(seq)-1)), None

for cap in (16, 32, 64, 128):
    m = JavaHashMap(cap if cap >= 16 else 16)
    for k, v in fields:
        m.put(k, v)
    it = [k for k, _ in m.items_in_iteration_order()]
    # candidate assignment: try all pairs for ONE1/ONE2 and VEND1/VEND2
    import itertools
    best = None
    for o1, o2 in itertools.permutations(ONES, 2):
        for v1, v2 in itertools.permutations(VENDS, 2):
            CAND = {'ONE1': [o1], 'ONE2': [o2], 'VEND1': [v1], 'VEND2': [v2]}
            obs = [o for o in OBS]
            ok, bad = True, None
            idx = {k: i for i, k in enumerate(it)}
            seq = []
            for o in obs:
                c = CAND.get(o, [o])
                ii = [idx[x] for x in c if x in idx]
                if not ii:
                    ok = False; break
                seq.append(min(ii))
            if ok and all(seq[i] < seq[i+1] for i in range(len(seq)-1)):
                print('CAP %d: MONOTONIC MATCH with ONE1=%s ONE2=%s VEND1=%s VEND2=%s' % (cap, o1, o2, v1, v2))
                print('  iteration idx seq:', seq)
                sys.exit(0)
    print('cap %d: no monotonic assignment (table=%d)' % (cap, len(it)))
print('H4 RESULT: no HashMap capacity reproduces the observed desc10 order')
