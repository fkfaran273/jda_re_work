# replica_recipe.py — which #0/H recipe reproduces the device's golden 192-B blob?
# Matrix over: #0 = all-zeros | captured | zeros+random dword, and H = captured |
# random. Same ORDER, same captured descriptors from fin_descs.json, same second.
import json
import os
import random
import secrets
import struct
import sys
from collections import defaultdict

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
sys.path.insert(0, REV)
from fin_vm2 import FinEx

F = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
W = json.load(open(os.path.join(REV, 'wh4_records.json'), encoding='utf-8'))
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
S0 = 0x5500000000
sec = F['target']['second']
want = bytes.fromhex(F['target']['blob_hex'])
D = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex']))
     for d in F['descs']}
H_gold = bytes.fromhex(W['mac_doFinal'][W['golden_sign_input_idx']]['hex'])
print('desc idx present:', sorted(D))
print('captured #4 == golden H :', D[4][1] == H_gold)
print('#0 captured len_dw', D[0][0], 'H captured len_dw', D[4][0])


def run(d0_mode, h_mode, tag):
    by = dict(D)
    if d0_mode == 'zeros':
        by[0] = (36, bytes(144))
    elif d0_mode == 'zeros+rand':
        b = bytearray(144)
        b[140:144] = struct.pack('>I', random.getrandbits(32))
        by[0] = (36, bytes(b))
    h = H_gold if h_mode == 'gold' else secrets.token_bytes(32)
    by[4] = (8, h)
    ex = FinEx(sec, [(by[i][0], 0, by[i][1]) for i in ORDER])
    st = ex.run(max_steps=20_000_000)
    sk = defaultdict(dict)
    for (s, n, v) in ex.emit_trace:
        sk[s][n] = v
    blob = b''.join(struct.pack('>I', sk[S0].get(i, 0)) for i in range(48))
    d = [i for i in range(192) if blob[i] != want[i]]
    print('%-28s status=%-11s diffbytes=%-4d %s'
          % (tag, st, len(d), 'BYTE-EXACT' if not d else 'first@%d' % d[0]))
    return blob, d


for d0m in ('zeros', 'zeros+rand', 'captured'):
    for hm in ('gold', 'rand'):
        run(d0m, hm, '#0=%s H=%s' % (d0m, hm))
