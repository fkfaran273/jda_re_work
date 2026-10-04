# h4_vs_H.py - the consequence of the #4 mislabel, measured.
#
# adj9_forge.make_signature_map() does  by[4] = (8, h_input)  and callers pass H
# there (--H random / borrowed H). But #4 is NOT H: it is the structured 32-byte
# record. So those arms produced a blob whose #4 slot holds a uniform MAC where a
# real device blob holds the structured record.
#
# Two measurements:
#   (1) transform battery: is #4 some simple transform of a captured H?
#   (2) VM behaviour: golden descriptors with #4 replaced by the REAL H
#       (= what the maker did) vs the structured #4 (= what the device did).
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

ORDER = json.load(open(os.path.join(HERE, 'adj9_material.json')))['va_order']
FD = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
R = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
SEC = FD['target']['second']
GOLD = bytes.fromhex(FD['target']['blob_hex'])
BASE = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex']))
        for d in FD['descs']}
D4 = BASE[4][1]


def hbytes(v):
    if isinstance(v, dict):
        for k in ('hex', 'data_hex', 'value', 'bytes'):
            if k in v:
                return hbytes(v[k])
    if isinstance(v, list):
        return bytes(v)
    return bytes.fromhex(str(v).replace('0x', '').strip())


HS = [hbytes(v) for v in R['mac_doFinal']]
print('captured H values (distinct): %d' % len(set(h.hex() for h in HS)))

# ---- (1) transform battery ---------------------------------------------------
print('\n=== (1) is #4 a transform of a captured H? ===')
cands = []
for h in set(h.hex() for h in HS):
    hb = bytes.fromhex(h)
    cands += [
        ('H', hb), ('rev(H)', hb[::-1]),
        ('H[:8]||H[:24]', hb[:8] + hb[:24]),
        ('H[8:]+H[:8]', hb[8:] + hb[:8]),
        ('swapped-words', b''.join(hb[i * 4:i * 4 + 4][::-1] for i in range(8))),
    ]
    for sh in range(1, 8):
        cands.append(('rotl%d' % sh, hb[sh:] + hb[:sh]))
        cands.append(('rotr%d' % sh, hb[-sh:] + hb[:-sh]))
hits = [n for n, v in cands if v == D4]
print('  direct matches to #4: %s' % (hits or 'NONE'))
allsig = [s['d4'].lower() for s in
          json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))
          if s.get('d4')]
mad = [n for n, v in cands if v.hex() in allsig]
print('  any transform matches any harvested #4: %s' % (mad or 'NONE'))


def run(d4):
    by = dict(BASE)
    by[4] = (8, d4)
    ex = FinEx(SEC, [(by[i][0], 0, by[i][1]) for i in ORDER])
    st = ex.run(max_steps=20_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    hdr = struct.unpack('>4I', make_header(SEC))
    stream = None
    for (s, n) in out:
        if tuple(out.get((s, k), 0) for k in range(4)) == hdr:
            stream = s
            break
    blob = (b''.join(struct.pack('>I', out.get((stream, k), 0)) for k in range(48))
            if stream is not None else b'')
    return st, ex.steps, blob


print('\n=== (2) VM behaviour of the #4 slot ===')
st, steps, blob = run(D4)
print('  #4 = captured structured record  : status=%-11s steps=%-9d equal_gold=%s'
      % (st, steps, blob == GOLD))
h0 = hbytes(R['mac_doFinal'][R['golden_sign_input_idx']])
st2, steps2, blob2 = run(h0)
law2 = blob2[:16] == make_header(SEC) if blob2 else False
diff = sum(1 for i in range(48)
           if (blob2[i * 4:i * 4 + 4] if blob2 else b'') != GOLD[i * 4:i * 4 + 4])
print('  #4 = the REAL H (maker\'s slot)  : status=%-11s steps=%-9d law=%-3s diff=%d/48'
      % (st2, steps2, 'OK' if law2 else 'BAD', diff))
print('  -> %s'
      % ('a real H in the #4 slot is a DIFFERENT blob from the device\'s'
         if blob2 != GOLD else 'identical'))