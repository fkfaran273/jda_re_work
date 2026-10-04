import json, struct, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
D = json.load(open(HERE + '/fin_descs.json'))
SEED = 1789240512
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
by0 = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex'])) for d in D['descs']}
def run(descs):
    ex = FinEx(SEED, descs); ex.run(max_steps=20_000_000)
    sinks = {}
    for (sn, n, v) in ex.emit_trace: sinks.setdefault(sn, {})[n] = v
    return [sinks.get(0x5500000000, {}).get(i, 0) for i in range(48)]
base = run([(by0[i][0], 0, by0[i][1]) for i in ORDER])
for name, new in (('#8 bit0 flip', by0[8][1][:1] + bytes([by0[8][1][1] ^ 1]) + by0[8][1][2:]),
                  ('#8 all 0xFF', b'\xff' * len(by0[8][1])),
                  ('#8 all zero', bytes(len(by0[8][1])))):
    by = dict(by0); by[8] = (by0[8][0], new)
    out = run([(by[i][0], 0, by[i][1]) for i in ORDER])
    print(name, '-> body diff %d/48' % sum(1 for i in range(48) if out[i] != base[i]), flush=True)
# template #0 vs current-install core0 sample (stability check)
core = json.load(open(HERE.replace('rev', 'device') + '/core0_samples.json'))
vm = [c for c in core if c.get('tag') == 'vm' and 'hex' in c]
if vm:
    cur = vm[0]['hex']
    print('template #0[:48]:', by0[0][1][:48].hex())
    print('current  #0[:48]:', cur[:96])
    print('PREFIX-EQUAL(48B):', cur[:96] == by0[0][1][:48].hex(), ' len tmpl=%d cur=%dB' % (len(by0[0][1]), len(cur)//2))
print('S8 DONE', flush=True)
