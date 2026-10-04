# Survey corpus.json: kinds, key orders, ts pairing blobs<->hs<->sign_inputs.
import json, struct, sys

HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
c = json.load(open(HERE + '/corpus.json'))
si, blobs, hs = c['sign_inputs'], c['blobs'], c['hs']

def parse_map(raw):
    out = []
    for ent in raw.split('\x02'):
        if ent:
            k, _, v = ent.partition('\x01')
            out.append((k, v))
    return out

print('=== sign_inputs summary ===')
kinds = {}
for i, e in enumerate(si):
    m = parse_map(e['map_order'])
    kv = dict(m)
    kind = kv.get('activity_kind', '?')
    kinds.setdefault(kind, []).append(i)
    print('%2d ts=%d kind=%-12s size=%s uuid=%s created=%s sc=%s' % (
        i, e['ts'], kind, e.get('map_size'), kv.get('android_uuid', '?')[:8],
        kv.get('created_at', '?'), kv.get('session_count', '?')))
print('kinds:', {k: len(v) for k, v in kinds.items()})

# key-order stability per kind
for kind, idxs in kinds.items():
    orders = ['\x02'.join(k for k, _ in parse_map(si[i]['map_order'])) for i in idxs]
    print('kind %-12s orders identical: %s' % (kind, len(set(orders)) == 1))

# full dump of one attribution-kind map if present
for kind in ('attribution', 'click', 'sdk_info', 'event'):
    if kind in kinds:
        i = kinds[kind][0]
        print('\n=== full canonical kind=%s idx=%d ===' % (kind, i))
        for k, v in parse_map(si[i]['map_order']):
            print('  %-26s = %s' % (k, v))
        break

print('\n=== ts pairing (blob <-> H <-> canonical within 3s) ===')
pairs = []
for bi, b in enumerate(blobs):
    cand_h = [k for k in hs if abs(k['ts'] - b['ts']) < 3000]
    cand_s = [s for s in si if abs(s['ts'] - b['ts']) < 3000]
    if cand_h and cand_s:
        pairs.append((bi, b, cand_h[0], cand_s[0]))
        print('blob[%d] ts=%d  H@+%dms  canon@+%dms kind=%s' % (
            bi, b['ts'], cand_h[0]['ts'] - b['ts'], cand_s[0]['ts'] - b['ts'],
            dict(parse_map(cand_s[0]['map_order'])).get('activity_kind')))
print('usable triples:', len(pairs))

# blob shape sanity: len, header MSB law, slot4==H?
for (bi, b, h, s) in pairs[:6]:
    raw = bytes.fromhex(b['hex'])
    dws = struct.unpack('>%dI' % (len(raw) // 4), raw)
    H = bytes.fromhex(h['H'])
    hit = any(dws[i:i+8] == struct.unpack('>8I', H) for i in range(4, 41))
    print('blob[%d] len=%d H-in-body-raw=%s hdr_msb_ok=%s' % (
        bi, len(raw), hit, all(raw[j] < 0x80 for j in (0, 4, 8, 12))))