# desc10_consistency.py — task_0010 premise test, fully OFFLINE:
# was every crafted arm "contaminated by wrong desc10 synthesis"? Compare the
# Python maker's OWN slot-10 bytes (adj9_forge.claims_for -> make_signature)
# against the PROVEN law (desc10_law.build_desc10) for
#   (a) the golden map  (should be byte-exact)
#   (b) a FRESH map with new gps/auid/timestamps (the real test)
import json
import os
import sys

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
sys.path.insert(0, REV)
import desc10_law as L
import adj9_forge as G

M = json.load(open(os.path.join(REV, 'adj9_material.json'), encoding='utf-8'))
base = bytes.fromhex(M['claims_base_hex'])
print('maker claims_base (slot 10) = %d B' % len(base))

# (a) golden map from the device's own capture
W = json.load(open(os.path.join(REV, 'wh4_records.json'), encoding='utf-8'))
si = W['sign_inputs'][W['golden_sign_input_idx']]
golden = {}
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        golden[k] = v
law_golden = L.build_desc10(golden, 'session').encode('latin1')
F = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
d10 = bytes.fromhex([d for d in F['descs'] if d['build_idx'] == 10][0]['data_hex'])
print('\n(a) golden map, law vs captured device desc10 :',
      'BYTE-EXACT' if law_golden == d10 else 'MISMATCH')
print('    maker base vs captured device desc10     :',
      'BYTE-EXACT' if base == d10 else 'MISMATCH')
if base != d10:
    for i in range(min(len(base), len(d10))):
        if base[i] != d10[i]:
            print('    first diff at %d: maker=%r device=%r'
                  % (i, base[i:i + 24], d10[i:i + 24]))
            break
    print('    lengths maker=%d device=%d' % (len(base), len(d10)))

# (b) FRESH map: new gps/auid/timestamps via the maker's own override path
fresh = dict(golden)
fresh['gps_adid'] = 'f3a52ba3-2d2b-4e1b-9dd3-fae4f9dcf371'
fresh['android_uuid'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
fresh['created_at'] = '2026-09-17T22:05:30.431Z+0530'
fresh['sent_at'] = '2026-09-17T22:05:30.431Z+0530'
fresh['installed_at'] = '2026-09-17T22:05:25.431Z+0530'
fresh['updated_at'] = '2026-09-17T22:05:25.431Z+0530'
ovr = {k: v for k, v in fresh.items() if k in set(M['claims_fields'])}
try:
    maker_fresh = G.claims_for(ovr)
except Exception as e:
    maker_fresh = None
    print('\n(b) maker override path raised:', type(e).__name__, e)
law_fresh = L.build_desc10(fresh, 'session').encode('latin1')
print('\n(b) FRESH map: law desc10 = %d B' % len(law_fresh))
if maker_fresh is not None:
    print('    maker desc10 = %d B  ->' % len(maker_fresh),
          'BYTE-EXACT' if maker_fresh == law_fresh else 'MISMATCH')
    if maker_fresh != law_fresh:
        n = min(len(maker_fresh), len(law_fresh))
        for i in range(n):
            if maker_fresh[i] != law_fresh[i]:
                print('    first diff at %d:' % i)
                print('      maker : %r' % maker_fresh[max(0, i - 40):i + 60])
                print('      law   : %r' % law_fresh[max(0, i - 40):i + 60])
                break
        else:
            print('    common prefix %d, then length differs' % n)

# (c) which keys does the maker's slot-10 actually contain, in order?
import re
keys_maker = re.findall(rb'([a-z_0-9]{3,})=', base)
seen = []
for k in keys_maker:
    k = k.decode()
    if k not in seen:
        seen.append(k)
print('\n(c) key order inside the maker desc10 (%d keys):' % len(seen))
print('   ', seen)
print('    law order  (%d keys):' % len(L.desc10_keys('session')))
print('   ', L.desc10_keys('session'))
print('    SAME ORDER:', seen == L.desc10_keys('session'))