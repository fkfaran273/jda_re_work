import time, sys, json, struct
sys.path.insert(0, '.')
import mint_pipeline as M

rows = json.load(open('all_signings.json', encoding='utf-8'))
pairs = {r['i']: r for r in json.load(open('pair_h3.json', encoding='utf-8'))}
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")


def mk(r):
    cl = bytes.fromhex(r['d10'])
    by = {0: (36, 0, bytes.fromhex(r['d0'])), 2: (1, 0, bytes.fromhex(r['d2'])),
          4: (8, 0, bytes.fromhex(r['d4'])), 9: (5, 0, D9), 8: (4, 0, D8),
          7: (1, 0, struct.pack('>I', len(cl))),
          10: (len(cl) // 4, 0, cl),
          5: (1, 0, struct.pack('>I', 0)), 6: (1, 0, struct.pack('>I', 0)),
          1: (0, 0, b''), 3: (0, 0, b'')}
    return [by[i] for i in M.VA_ORDER]


r = rows[7]
sec = int(pairs[7]['second'])
cap = bytes.fromhex(pairs[7]['blob'])
t = time.time()
b, info = M.finex_mint(mk(r), sec)
print('time %.1fs' % (time.time() - t), info)
print('match', b == cap)
w = struct.unpack('>48I', b)
d0w = list(struct.unpack('>36I', bytes.fromhex(r['d0'])))
d4w = list(struct.unpack('>8I', bytes.fromhex(r['d4'])))
d2w = struct.unpack('>I', bytes.fromhex(r['d2']))[0]
print('W0=%08x X=%08x T0=%08x T1=%08x F4=%08x S=%08x' %
      (d0w[0], d0w[1], d0w[2], d0w[3], d4w[4], d2w))
print('d0[4:8]', ['%08x' % x for x in d0w[4:8]])
print('d4', ' '.join('%08x' % x for x in d4w))
print('body', ' '.join('%08x' % x for x in w[4:]))
