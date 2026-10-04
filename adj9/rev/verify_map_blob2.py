# verify_map_blob2.py - task_0002 proof: adj9_forge.make_signature_map() builds the
# blob for an ARBITRARY map from the desc10 LAW and reproduces the device's own
# golden 192-B blob BYTE-EXACT (captured #0/#4 inputs, law #10/#7).
import json
import os
import sys

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
sys.path.insert(0, REV)
import adj9_forge as G

W = json.load(open(os.path.join(REV, 'wh4_records.json'), encoding='utf-8'))
F = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
gi = W['golden_sign_input_idx']
si = W['sign_inputs'][gi]
val = {}
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        val[k] = v

sec = F['target']['second']
want = bytes.fromhex(F['target']['blob_hex'])
print('map keys %d | second %d | golden %d B' % (len(val), sec, len(want)))

fresh = dict(val)
fresh['gps_adid'] = 'f3a52ba3-2d2b-4e1b-9dd3-fae4f9dcf371'
fresh['android_uuid'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
for k in ('created_at', 'sent_at'):
    fresh[k] = '2026-09-17T22:05:30.431Z+0530'
for k in ('installed_at', 'updated_at'):
    fresh[k] = '2026-09-17T22:05:25.431Z+0530'

for tag, m in (('GOLDEN map', val), ('FRESH map ', fresh)):
    st, blob, h_used = G.make_signature_map(m, 'session', sec)
    d = [i for i in range(192) if blob[i] != want[i]]
    print('%-11s status=%-11s blob=%d B  %s'
          % (tag, st, len(blob),
             'BYTE-EXACT vs golden' if not d
             else 'differs from golden (%d B, first@%d) — expected for a new map'
             % (len(d), d[0])))
    print('             header == Random3(second): %s | #4 input: %s'
          % (blob[:16] == G.make_header(sec), h_used[:8].hex()))