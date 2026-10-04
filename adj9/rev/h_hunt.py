# h_hunt.py - direct hypothesis tests against 6 self-paired live signings
import json, hashlib, hmac, struct, itertools, re, sys
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9')
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
P = json.load(open(REV + r'\live_pairs.json', encoding='utf-8'))
assert len(P) == 6 and all(p['toString'] and p['order'] and p['blob'] and p['H'] for p in P)

def dw(b, off=4, n=None):
    n = n if n is not None else (len(b) - off) // 4
    return [struct.unpack_from('>I', b, off + 4 * i)[0] for i in range(n)]

KEYS = [b'jut9tib0eeps', b'Quoh8uafohgh7CahM2h', b'adj9', b'key2', b'1500000',
        b'com.penti.app', b'android5.7.0', b'5.0.0', b'KlcAG2cbAAsKSl1KVi0FGiJbDHMI']

print('=== H1: keyless/static-key candidates for H (arg3) ===')
any_pass = False
for p in P:
    ts = p['toString'].encode()
    mo = p['order'].encode()
    blobs_msg = {'sha(toString)': hashlib.sha256(ts).digest(),
                 'sha(order)': hashlib.sha256(mo).digest(),
                 'sha(order+toString)': hashlib.sha256(mo + ts).digest(),
                 'sha(toString+order)': hashlib.sha256(ts + mo).digest(),
                 'sha(toString_noWS)': hashlib.sha256(p['toString'].replace(', ', '').encode()).digest()}
    for k in KEYS:
        blobs_msg['hmac(%s,toString)' % k[:6].decode('latin1')] = hmac.new(k, ts, hashlib.sha256).digest()
        blobs_msg['hmac(%s,order)' % k[:6].decode('latin1')] = hmac.new(k, mo, hashlib.sha256).digest()
    hb = bytes.fromhex(p['H'])
    hits = [n for n, d in blobs_msg.items() if d == hb]
    if hits_ := hits:
        any_pass = True
        print('  sample %d PASS: %s' % (p['i'], hits))
print('H1 (static/keyless H):', 'PASS' if any_pass else 'FAIL (0/6 x %d candidates) - H needs key2, as dex says' % (5 + 2 * len(KEYS)))

print('=== H2: body dword equality across same-map pairs (H-independence map) ===')
B = [bytes.fromhex(p['blob']) for p in P]
DW = [[struct.unpack_from('>I', b, 4 * i)[0] for i in range(48)] for b in B]
for a, b in ((0, 3), (1, 4), (2, 5)):
    eq = [k for k in range(48) if DW[a][k] == DW[b][k]]
    same_map = len(P[a]['toString']) == len(P[b]['toString'])
    print('  pair %d-%d sameMap=%s equal_dwords=%d %s' % (a, b, same_map, len(eq), eq[:10]))
# cross-map pair for baseline
print('  baseline 0-1 (diff maps): equal =', sum(1 for k in range(48) if DW[0][k] == DW[1][k]))

print('=== H3: desc10 emission order vs canonical.v5_map_order ===')
from canonical import v5_map_order
D = json.load(open(REV + r'\fin_descs.json', encoding='utf-8'))
d10 = bytes.fromhex([d for d in D['descs'] if d['build_idx'] == 10][0]['data_hex']).decode('latin1')
order5 = list(v5_map_order())
print('  v5_map_order len:', len(order5), order5[:6], '...')
idx5 = {k: i for i, k in enumerate(order5)}
obs_keys = ['adj_verification','android_uuid','api_level','app_token','app_version','created_at',
            'device_name','device_type','environment','gps_adid','gps_adid_src','hardware_name',
            'store#1','installed_at','os_build','os_name','os_version','package_name',
            'adj_signing_id','?1a','store#2','?1b','updated_at','activity_kind','client_sdk',
            'headers_id','native_version']
known = [k for k in obs_keys if k in idx5]
prev = -1; mono = True; breaks = []
for k in known:
    i = idx5.get(k)
    if i is None: continue
    if i < prev:
        mono = False; breaks.append(k)
    prev = i
print('  monotonic subset of v5_map_order:', mono, '| breaks at:', breaks)
# where would breaks resolve if we allow the two mystery '1's + vendings interleaved?
seq5 = [idx5[k] for k in known if k in idx5]
print('  idx sequence:', seq5)
inv = [(seq5[i] > seq5[i+1]) for i in range(len(seq5)-1)]
print('  descents:', sum(inv), 'of', len(inv))
