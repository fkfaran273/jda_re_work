import json, struct, sys, secrets
sys.path.insert(0, r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
from fin_vm2 import FinEx

D = json.load(open(HERE + '/fin_descs.json'))
by = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex']))
      for d in D['descs']}
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
SEED = 1789240512
CORP = json.load(open(HERE + '/corpus.json'))
gold_hex = None
for r in CORP['rapid']:
    if r['sec'] == SEED:
        gold_hex = r['hex']
        break
GOLD_BLOB = bytes.fromhex(gold_hex) if gold_hex else None
print('gold blob found for sec', SEED, ':', GOLD_BLOB is not None, flush=True)


def run(seq, sec=SEED):
    ex = FinEx(sec, seq)
    ex.run(max_steps=20_000_000)
    sinks = {}
    for (s, n, v) in ex.emit_trace:
        sinks.setdefault(s, {})[n] = v
    return b''.join(struct.pack('>I', sinks[0x5500000000].get(i, 0))
                    for i in range(48))


def diffs(A, B):
    return sum(1 for k in range(48)
               if struct.unpack('>I', A[k*4:k*4+4])[0] !=
                  struct.unpack('>I', B[k*4:k*4+4])[0])


def seq_with(idx, newdata, newlen=None):
    out = []
    for i in ORDER:
        if i == idx:
            out.append((newlen if newlen is not None else by[i][0], 0, newdata))
        else:
            out.append((by[i][0], 0, by[i][1]))
    return out


base_seq = [(by[i][0], 0, by[i][1]) for i in ORDER]
print('baseline (template inputs, correct seed)...', flush=True)
A = run(base_seq)
if GOLD_BLOB:
    gd = diffs(A, GOLD_BLOB)
    print('  template-run vs GOLD bytes: diff', gd, '/48',
          '| hdr match:', A[:16] == GOLD_BLOB[:16], flush=True)
    if gd == 0:
        print('  HARNESS ANCHORED: baseline == genuine blob, byte-exact', flush=True)
    else:
        print('  WARNING: baseline does NOT reproduce GOLD - harness invalid', flush=True)
print('  A body head:', A[16:32].hex(), flush=True)

Ht = by[4][1]
hf = bytearray(Ht); hf[0] ^= 1
variants = [
    ('H_bit0flip',   4,  bytes(hf), None),
    ('H_random',     4,  secrets.token_bytes(32), None),
    ('#2_zero',      2,  bytes(len(by[2][1])), None),
    ('#2_bit0flip',  2,  bytes(bytearray([by[2][1][0] ^ 1]) + by[2][1][1:]), None),
    ('#8_zero',      8,  bytes(len(by[8][1])), None),
    ('#10_bit0flip', 10, bytes(bytearray([by[10][1][0] ^ 1]) + by[10][1][1:]), None),
]
for name, idx, nd, nl in variants:
    print(f'{name} running...', flush=True)
    B = run(seq_with(idx, nd, nl))
    print(f'  {name}: diff_vs_baseline={diffs(A, B)}/48', flush=True)
print('ANCHORED MATRIX DONE', flush=True)
