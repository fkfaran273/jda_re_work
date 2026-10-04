# verify_map_blob.py - task_0002 proof: the maker can now build a blob for an
# ARBITRARY map from the desc10 LAW alone. Test = reproduce the device's own
# golden 192-B blob using a law-built desc10 (not the golden claims base) plus
# the captured per-call slots (#0/#2/#4) and the captured H.
import json
import os
import sys

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
sys.path.insert(0, REV)
import adj9_forge as G
import desc10_law as L

W = json.load(open(os.path.join(REV, 'wh4_records.json'), encoding='utf-8'))
F = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
gi = W['golden_sign_input_idx']
si = W['sign_inputs'][gi]
val = {}
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        val[k] = v

sec = F['target']['second']                    # header law second of the golden call
H = bytes.fromhex(W['mac_doFinal'][gi]['hex'])  # captured HMAC output
want = bytes.fromhex(F['target']['blob_hex'])
D = {d['build_idx']: d['data_hex'] for d in F['descs']}
d0 = bytes.fromhex(D[0])
print('captured #0: %d B  #2: %s  #8: %s' % (
    len(d0), D.get(2), (D.get(8) or '')[:16]))


def show(tag, blob):
    same = blob == want
    d = [i for i in range(192) if blob[i] != want[i]]
    print('%-22s %d B  %s  diffbytes=%d%s'
          % (tag, len(blob), 'BYTE-EXACT' if same else 'MISMATCH',
             len(d), '' if not d else ' first@%d' % d[0]))
    return same


st, blob_z, _ = G.make_signature_map(val, 'session', sec, H)          # zeroed #0
print('status(zero-core) =', st)
show('zero-core #0', blob_z)

st, blob_c, _ = G.make_signature_map(val, 'session', sec, H,
                                     extra={0: (len(d0) // 4, d0)})
print('status(captured #0) =', st)
show('captured #0', blob_c)

# where in the body do the two variants diverge, and how do they map to #0?
print('\nzero-core blob dwords :', ' '.join('%08x' % x for x in
      __import__('struct').unpack('>48I', blob_z)[:12]), '...')
print('#0 dwords (first 12)  :', ' '.join('%08x' % x for x in
      __import__('struct').unpack('>36I', d0)[:12]))
print('#0 tail (last 8 dw)   :', ' '.join('%08x' % x for x in
      __import__('struct').unpack('>36I', d0)[28:]))
print('second      :', sec)
print('law desc10  : %d B' % len(L.build_desc10(val, 'session').encode('latin1')))
print('status      :', st)
print('blob        : %d B' % len(blob))
print('header law  :', blob[:16] == G.make_header(sec) if hasattr(G, 'make_header')
      else 'n/a')
same = blob == want
print('GOLDEN BLOB :', 'BYTE-EXACT' if same else 'MISMATCH')
if not same:
    d = [i for i in range(192) if blob[i] != want[i]]
    print('  differing bytes: %d (first %s)' % (len(d), d[:12]))
    print('  first diff at byte %s' % (d[0] if d else '-'))
    i = d[0] if d else 0
    print('    got :', blob[max(0, i - 8):i + 16].hex())
    print('    want:', want[max(0, i - 8):i + 16].hex())
