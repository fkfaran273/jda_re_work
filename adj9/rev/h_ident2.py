# h_ident2.py - is descriptor #4 the captured H? Decisive comparison.
#
# rev/wh4_records.json holds the authoritative pairing for the GOLDEN signing
# (the one fin_descs.json reproduces 48/48):  nsigns / sign_inputs / canonicals
# / mac_doFinal  (+ golden indices). H = mac_doFinal (the Mac.doFinal output the
# SDK hands to nSign as arg3). If descriptor #4 is H they must be equal.
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
R = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
print('keys: %s' % list(R.keys()))
print('golden nsign idx=%s sign_input idx=%s'
      % (R.get('golden_nsign_idx'), R.get('golden_sign_input_idx')))
print()

mac = R['mac_doFinal']
print('mac_doFinal entries: %d' % len(mac))


def hx(v):
    if isinstance(v, str):
        return v.lower()
    if isinstance(v, list):
        return bytes(v).hex()
    if isinstance(v, dict) and 'hex' in v:
        return v['hex'].lower()
    return str(v)[:80]


H = [hx(v) for v in mac]
for i, h in enumerate(H):
    print('  H[%d] len=%d head=%s' % (i, len(h) // 2, h[:32]))
print()

fd = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
d4 = [d for d in fd['descs'] if d['build_idx'] == 4][0]['data_hex'].lower()
print('fin_descs[#4] = %s' % d4)
print('golden blob  = %s' % fd['target']['blob_hex'].lower()[:64] + '…')
print()

HSET = set(H)
print('fin_descs[#4] in H set      : %s' % (d4 in HSET))
print('fin_descs[#4] head matches H: %s'
      % any(d4[:16] == h[:16] for h in H))

# does ANY H occur anywhere in the golden 192-B blob?
blob = bytes.fromhex(fd['target']['blob_hex'])
for i, h in enumerate(H):
    hb = bytes.fromhex(h)
    pos = blob.find(hb)
    if pos >= 0:
        print('  H[%d] found inside the golden blob at offset %d' % (i, pos))
print('any H substring in the blob: %s'
      % any(bytes.fromhex(h) in blob for h in H))

# where DOES H live in the descriptor set? scan every descriptor for a
# 32-byte window equal to any H (and for the 8-dw emitted form of any H)
print()
print('=== does any descriptor contain an H (raw or as BE dwords)? ===')
for d in fd['descs']:
    data = bytes.fromhex(d['data_hex'])
    for i, h in enumerate(H):
        hb = bytes.fromhex(h)
        beform = b''.join(struct.pack('>I', v) for v in
                          struct.unpack('<8I', hb))
        tags = []
        if hb in data:
            tags.append('raw')
        if beform in data:
            tags.append('BE-dwords')
        if data in hb or hb.startswith(data):
            tags.append('prefix-of-H')
        if tags:
            print('  build_idx %-3d len_dw %-3d contains H[%d] as %s'
                  % (d['build_idx'], d['len_dw'], i, '/'.join(tags)))
print('(no line above == no descriptor carries the captured H)')
print()

# sanity: the documented invariant
print('=== invariant check (slice: H is NOT in the blob — h_crack.py) ===')
print('  blob.find(H) == -1 for all H : %s'
      % all(blob.find(bytes.fromhex(h)) == -1 for h in H))