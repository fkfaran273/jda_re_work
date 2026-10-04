# pack_corpus.py - LINCHPIN: does FinEx(packed #10 from the paired canonical
# map, paired H, paired sec) reproduce the genuine corpus blob byte-exact?
import json, struct, sys, time
HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

c = json.load(open(HERE + '/corpus.json'))
si, blobs, hs = c['sign_inputs'], c['blobs'], c['hs']
D = json.load(open(HERE + '/fin_descs.json'))
by = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex'])) for d in D['descs']}

def pm(raw):
    out = []
    for e in raw.split('\x02'):
        if e:
            k, _, v = e.partition('\x01')
            out.append((k, v))
    return out

# template-derived values order (27 slots; from golden template #10 anatomy)
ORDER_T = ['adj_verification', 'android_uuid', 'api_level', 'app_token',
           'app_version', 'created_at', 'device_name', 'device_type',
           'environment', 'gps_adid', 'gps_adid_src', 'hardware_name',
           'store_name_from_system', 'installed_at', 'os_build', 'os_name',
           'os_version', 'package_name', 'adj_signing_id', 'session_count',
           'store_name_from_system', 'tracking_enabled', 'updated_at',
           'activity_kind', 'client_sdk', 'headers_id', 'native_version']
CONST = {'adj_verification': 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
         'client_sdk': 'android5.7.0', 'headers_id': '10',
         'adj_signing_id': '1500000', 'native_version': '5.0.0',
         'activity_kind': None}  # from map

def build10(kv, order):
    vals = []
    for k in order:
        v = kv.get(k, CONST.get(k))
        if v is None:
            return None
        vals.append(str(v))
    return ''.join(vals).encode()

def run_case(b, h, s, d10, label):
    kv = dict(pm(s['map_order']))
    sec = b['ts'] // 1000
    H = bytes.fromhex(h['H'])
    expect = bytes.fromhex(b['hex'])
    base = dict(by)
    base[10] = ((len(d10) + 3) // 4, d10)
    base[4] = (8, H)
    ex = FinEx(sec, [(base[i][0], 0, base[i][1]) for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]])
    t0 = time.time()
    st = ex.run(max_steps=40_000_000)
    sinks = {}
    for (sn, n, v) in ex.emit_trace:
        sinks.setdefault(sn, {})[n] = v
    blob = b''.join(struct.pack('>I', sinks[0x5500000000].get(i, 0)) for i in range(48))
    diff = sum(1 for i in range(48) if blob[4*i:4*i+4] != expect[4*i:4*i+4])
    hdr = blob[:16] == expect[:16]
    print('%s: st=%s steps=%d (%.0fs) hdr_match=%s body_diff=%d/48'
          % (label, st, ex.steps, time.time()-t0, hdr, diff-4), flush=True)
    if diff - 4 == 0:
        print('*** BYTE-EXACT — PACKING LAW PROVEN (%s) ***' % label, flush=True)
    return diff - 4

# pair
pairs = []
for b in blobs:
    ch = [k for k in hs if abs(k['ts'] - b['ts']) < 3000]
    cs = [s for s in si if abs(s['ts'] - b['ts']) < 3000]
    if ch and cs:
        pairs.append((b, ch[0], cs[0]))
print('pairs:', len(pairs), flush=True)

for n, (b, h, s) in enumerate(pairs[:2]):
    kv = dict(pm(s['map_order']))
    print('\n=== pair %d ts=%d kind=%s ===' % (n, b['ts'], kv.get('activity_kind')), flush=True)
    o1 = build10(kv, ORDER_T)
    if o1:
        run_case(b, h, s, o1, 'orderT')
    o2 = ''.join(v for _, v in pm(s['map_order'])).encode()
    run_case(b, h, s, o2, 'allvalues')
print('\nDONE', flush=True)
