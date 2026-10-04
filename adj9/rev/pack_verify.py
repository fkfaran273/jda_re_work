# pack_verify.py — OFFLINE proof of the values-only packing law.
# For each corpus triple (blob, H, canonical): rebuild all 11 descriptors,
# run FinEx, compare to the captured blob. Template descs (#0/#9/#2/...) are
# valid because corpus blobs came from the same moto device.
# Selector derived from the 360B template walk (27 fixed slots, in order):
SEL_SESSION = ['adj_verification', 'android_uuid', 'api_level', 'app_token',
               'app_version', 'created_at', 'device_name', 'device_type',
               'environment', 'gps_adid', 'gps_adid_src', 'hardware_name',
               'store_name_from_system', 'installed_at', 'os_build', 'os_name',
               'os_version', 'package_name', 'adj_signing_id', 'session_count',
               'initiating_package_name', 'ui_mode', 'updated_at',
               'activity_kind', 'client_sdk', 'headers_id', 'native_version']

import json, struct, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from verify_saz_like_server import make_header

corpus = json.load(open(HERE + '/corpus.json'))
D = json.load(open(HERE + '/fin_descs.json'))
TMPL = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex'])) for d in D['descs']}
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]

def parse_map(raw):
    out = []
    for ent in raw.split('\x02'):
        if ent:
            k, _, v = ent.partition('\x01')
            out.append((k, v))
    return out

def pack10(m, sel):
    s = ''.join(m[k] for k in sel if k in m).encode('utf-8')
    pad = (-len(s)) % 4
    return s + (b'\x00' * pad if pad else b'')
    # note: if pad needed, len_dw loses the tail -> will show up as mismatch

def build_descs(m, H, t10):
    by = dict(TMPL)
    by[10] = (len(t10) // 4, t10)
    by[4] = (8, H)
    by[7] = (1, struct.pack('>I', len(t10)))
    return [(by[i][0], 0, by[i][1]) for i in ORDER]

def blob_dwords(raw):
    return struct.unpack('>%dI' % (len(raw) // 4), raw)

si, blobs, hs = corpus['sign_inputs'], corpus['blobs'], corpus['hs']
triples = []
for b in blobs:
    ch = sorted([h for h in hs if abs(h['ts'] - b['ts']) < 3000],
                key=lambda h: abs(h['ts'] - b['ts']))
    cs = sorted([s for s in si if abs(s['ts'] - b['ts']) < 3000],
                key=lambda s: abs(s['ts'] - b['ts']))
    if ch and cs:
        m = dict(parse_map(cs[0]['map_order']))
        if m.get('activity_kind') == 'session':
            triples.append((b, ch[0], cs[0], m))
print('session triples:', len(triples))

def find_sec(raw, ts):
    for d in (0, 1, -1, 2, -2):
        sec = ts // 1000 + d
        try:
            if make_header(sec) == raw[:16]:
                return sec
        except Exception:
            pass
    return None

allok = True
for (b, h, s, m) in triples:
    raw = bytes.fromhex(b['hex'])
    sec = find_sec(raw, b['ts'])
    if sec is None:
        print('blob ts=%d: NO header sec match' % b['ts']); allok = False; continue
    t10 = pack10(m, SEL_SESSION)
    descs = build_descs(m, bytes.fromhex(h['H']), t10)
    ex = FinEx(sec, descs)
    ex.run(max_steps=20_000_000)
    sinks = {}
    for (sn, n, v) in ex.emit_trace:
        sinks.setdefault(sn, {})[n] = v
    out = b''.join(struct.pack('>I', sinks.get(0x5500000000, {}).get(i, 0))
                   for i in range(48))
    ok = out == raw
    allok &= ok
    ndiff = sum(1 for i in range(48)
                if struct.unpack('>I', out[i*4:i*4+4])[0] !=
                   blob_dwords(raw)[i]) if not ok else 0
    print('blob ts=%d kind=%s sc=%s sec=%d -> %s (%d/48 dw diff)'
          % (b['ts'], m.get('activity_kind'), m.get('session_count'), sec,
             'MATCH' if ok else 'DIFF', ndiff))
    if not ok:
        got = blob_dwords(out); exp = blob_dwords(raw)
        bad = [(i, hex(got[i]), hex(exp[i])) for i in range(48) if got[i] != exp[i]][:8]
        print('   first diffs (idx got exp):', bad)
        print('   packed len=%d (want dw7=%d)' % (len(t10), len(t10) // 4))

print('SESSION PACKING LAW:', 'PROVEN' if allok else 'NOT PROVEN')

# template #0 vs current install core record
core = json.load(open(HERE.replace('rev', 'device') + '/core0_samples.json'))
vm = [c for c in core if c.get('tag') == 'vm' and 'hex' in c]
if vm:
    cur = vm[0]['hex']
    t0 = TMPL[0][1].hex()
    print('\ncore0 current-install[:96] =', cur[:96])
    print('template      #0      [:96] =', t0[:96])
    print('#0 equal:', cur == t0, ' (len %d vs %d)' % (len(cur) // 2, len(t0)))