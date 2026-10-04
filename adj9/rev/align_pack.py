#!/usr/bin/env python3
"""align_pack.py — derive the EXACT #10 packing law from the corpus.

Model under test (slice 94):
  server re-derives canonical(query) -> packs descriptor #10 (key-less value
  concatenation over a fixed field subset) -> VM(canonical, H-from-blob) ->
  compares body.  Our forged bodies always carried the TEMPLATE's claims,
  not the packing of the query we actually sent -> silent Organic.

Step 1: find the template's own canonical (created_at 2026-09-12T21:15:11.678Z+0200)
Step 2: segment template #10 greedily against that canonical's value pool
Step 3: apply the derived law to canon[0] (paired blob[0]/hs[0]) and print
        the packed record for FinEx verification in pack_verify2.py
"""
import json, struct, sys, os

HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
sys.stdout.reconfigure(line_buffering=True)

c = json.load(open(HERE + '/corpus.json'))
si, blobs, hs = c['sign_inputs'], c['blobs'], c['hs']
D = json.load(open(HERE + '/fin_descs.json'))
by = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex'])) for d in D['descs']}
T10 = by[10][1]
print('template #10 len:', len(T10))

def parse_map(raw):
    out = []
    for ent in raw.split('\x02'):
        if ent:
            k, _, v = ent.partition('\x01')
            out.append((k, v))
    return out

# ---- step 1: find template's own canonical ------------------------------
tmpl_can = None
for i, e in enumerate(si):
    m = dict(parse_map(e['map_order']))
    if m.get('created_at') == '2026-09-12T21:15:11.678Z+0200':
        tmpl_can = (i, e, m)
        break
print('template canonical found:', tmpl_can is not None if tmpl_can else False,
      '' if not tmpl_can else ('idx=%d kind=%s' % (tmpl_can[0], tmpl_can[2].get('activity_kind'))))

# ---- step 2: greedy segmentation of T10 ---------------------------------
if tmpl_can:
    i, e, m = tmpl_can
    vals = m  # dict k->v (LinkedHashMap order preserved in map_order)
    # candidate field order: try the canonical's own key order first
    order_keys = [k for k, _ in parse_map(e['map_order'])]
    pos = 0
    seq = []
    used = set()
    ok = True
    for k in order_keys:
        v = vals[k]
        if T10[pos:pos+len(v)] == v.encode():
            seq.append((k, v)); pos += len(v); used.add(k)
        else:
            ok = False
            print('  order-mismatch at key %-26s expected %r got %r' % (k, v[:20], T10[pos:pos+20]))
            break
    print('canonical-order packing:', 'EXACT' if (ok and pos == len(T10)) else 'no (pos=%d/%d)' % (pos, len(T10)))
    if not (ok and pos == len(T10)):
        # greedy: repeatedly match the longest value that fits at pos
        pos = 0; seq2 = []; pool = sorted(vals.items(), key=lambda kv: -len(kv[1]))
        guard = 0
        while pos < len(T10) and guard < 60:
            guard += 1
            hit = None
            for k, v in pool:
                vb = v.encode()
                if v and T10[pos:pos+len(vb)] == vb:
                    # longest match wins; ties broken by canonical order
                    if hit is None or len(v) > len(hit[1]):
                        hit = (k, v)
            if hit is None:
                print('  greedy STUCK at pos=%d rest=%r' % (pos, T10[pos:pos+30]))
                break
            seq2.append(hit); pos += len(hit[1])
        print('greedy segments:', len(seq2), 'consumed', pos, 'of', len(T10))
        for k, v in seq2:
            print('   %-26s %r' % (k, v[:40]))
        missing = [k for k in vals if k not in dict(seq2)]
        print('canonical keys NOT in #10:', missing)

# ---- step 3: pack canon[0] with derived law, for FinEx check ------------
# use greedy law if template canonical found, else fall back to observed order
LAW = None
if tmpl_can:
    try:
        LAW = [k for k, _ in seq2]
    except NameError:
        LAW = None
if LAW is None:
    LAW = ['adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
           'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
           'gps_adid_src', 'hardware_name', 'store_name_from_system', 'installed_at',
           'os_build', 'os_name', 'os_version', 'package_name', 'adj_signing_id',
           'session_count', 'initiating_package_name', 'ui_mode', 'updated_at',
           'activity_kind', 'client_sdk', 'headers_id', 'native_version']
print('\nLAW (%d fields): %s' % (len(LAW), LAW))

e0 = si[0]
m0 = dict(parse_map(e0['map_order']))
m0.setdefault('adj_verification', 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI')
m0.setdefault('client_sdk', 'android5.7.0')
m0.setdefault('headers_id', '10')
m0.setdefault('adj_signing_id', '1500000')
m0.setdefault('native_version', '5.0.0')
m0.setdefault('algorithm', 'adj9')
miss = [k for k in LAW if k not in m0]
print('canon[0] missing law fields:', miss)
if not miss:
    packed = ''.join(m0[k] for k in LAW).encode()
    print('canon[0] packed len:', len(packed), '(dw7=%d)  blob[0] dw7 says #10 dw len' )
    raw = bytes.fromhex(blobs[0]['hex'])
    dws = struct.unpack('>48I', raw)
    print('blob[0] dw7 (desc7 dword len) =', dws[7], '-> #10 byte len =', dws[7]*4)
    open(HERE + '/packed_canon0.bin', 'wb').write(packed)
    print('packed written to packed_canon0.bin')
    print('paired: blob[0] ts=%d  canon[0] ts=%d  H ts=%d  sec=%d' % (
        blobs[0]['ts'], e0['ts'], hs[0]['ts'], blobs[0]['ts'] // 1000))
