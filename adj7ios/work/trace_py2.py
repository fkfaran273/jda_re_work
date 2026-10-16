import binascii, sys
sys.path.insert(0, '.')
import importlib
m = importlib.import_module('adj7ios_pure_py27')
SEED = m.SEED
print('SEED type', type(SEED), 'len', len(SEED))
kb = bytearray(SEED)
W = [list(kb[i * 4:i * 4 + 4]) for i in range(8)]
print('W lens', [len(w) for w in W])
print('W7', W[7])
SB = bytearray(m.AES_SBOX)
print('sbox lens', len(SB), 'first', SB[:4])
t = list(W[7])
try:
    x = [SB[b] for b in t[1:] + t[:1]]
    print('sub ok', x)
except Exception as e:
    print('sub ERR', repr(e), 't=', t, 'max=', max(t) if t else None)
