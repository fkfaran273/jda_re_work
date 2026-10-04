# tpl_swap_test.py - decisive: template #10 + value swaps (make_signature law)
# applied to corpus pair -> must reproduce the genuine blob byte-exact.
import json, struct, sys, time
HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
sys.path.insert(0, HERE)
from fin_vm2 import FinEx

c = json.load(open(HERE + '/corpus.json'))
si, blobs, hs = c['sign_inputs'], c['blobs'], c['hs']
D = json.load(open(HERE + '/fin_descs.json'))
by = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex'])) for d in D['descs']}
T10 = by[10][1]

def pm(raw):
    out = []
    for e in raw.split('\x02'):
        if e:
            k, _, v = e.partition('\x01')
            out.append((k, v))
    return out

print('=== corpus kinds ===', flush=True)
kinds = {}
for i, s in enumerate(si):
    kv = dict(pm(s['map_order']))
    kinds.setdefault(kv.get('activity_kind', '?'), []).append(i)
print(kinds, flush=True)

pairs = []
for b in blobs:
    ch = [k for k in hs if abs(k['ts'] - b['ts']) < 3000]
    cs = [s for s in si if abs(s['ts'] - b['ts']) < 3000]
    if ch and cs:
        pairs.append((b, ch[0], cs[0]))

def swap_eq(d, old, new):
    if old in d and len(old) == len(new):
        return d.replace(old, new)
    return d

for n, (b, h, s) in enumerate(pairs[:3]):
    kv = dict(pm(s['map_order']))
    sec = b['ts'] // 1000
    H = bytes.fromhex(h['H'])
    expect = bytes.fromhex(b['hex'])
    d10 = T10
    # stamps (equal-length forced in make_signature; verify here)
    d10 = swap_eq(d10, b'2026-09-12T21:15:11.678Z+0200', kv['created_at'].encode())
    d10 = swap_eq(d10, b'2026-09-08T12:20:49.782Z+0200', kv['installed_at'].encode())
    d10 = swap_eq(d10, b'2026-09-10T07:26:18.015Z+0200', kv['updated_at'].encode())
    d10 = swap_eq(d10, b'f476b3d4-e0b1-4707-bc43-6153d17f7f8c', kv['gps_adid'].encode())
    d10 = swap_eq(d10, b'd773f47f-fc0e-4994-9cf7-7c3cf5bb6368', kv['android_uuid'].encode())
    d10 = swap_eq(d10, b'moto g42', kv['device_name'].encode())
    d10 = swap_eq(d10, b'S2SE32.28-28-4', kv['os_build'].encode())   # os_build slot (2x in tpl)
    d10 = swap_eq(d10, b'12com.penti.app', (kv['os_version'] + 'com.penti.app').encode())
    d10 = swap_eq(d10, b'31jut9tib0eeps', (kv['api_level'] + 'jut9tib0eeps').encode())
    d10 = swap_eq(d10, b'3.13.9', kv['app_version'].encode())
    sc_new = (kv.get('session_count') or '1').encode()
    d10 = swap_eq(d10, b'1500000\x01', b'')  # no-op placeholder (never matches)
    # session_count slot: '...1500000' + sc + 'com.android.vending'
    d10 = swap_eq(d10, b'15000001com.android.vending',
                  b'1500000' + sc_new + b'com.android.vending')
    base = dict(by)
    base[10] = ((len(d10) + 3) // 4, d10)
    base[4] = (8, H)
    base[7] = (1, struct.pack('>I', len(d10)))
    ex = FinEx(sec, [(base[i][0], 0, base[i][1]) for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]])
    t0 = time.time()
    st = ex.run(max_steps=40_000_000)
    sinks = {}
    for (sn, nn, v) in ex.emit_trace:
        sinks.setdefault(sn, {})[nn] = v
    blob = b''.join(struct.pack('>I', sinks[0x5500000000].get(i, 0)) for i in range(48))
    diffs = [i for i in range(48) if blob[4*i:4*i+4] != expect[4*i:4*i+4]]
    print('pair%d ts=%d kind=%s: st=%s (%.0fs) hdr=%s body_diff=%d/48 %s'
          % (n, b['ts'], kv.get('activity_kind'), st, time.time()-t0,
             blob[:16] == expect[:16], len(diffs)-4,
             '*** EXACT ***' if not diffs[4:] else diffs[4:12]), flush=True)
print('DONE', flush=True)
