"""_p2.py — is the body whitening keystream region-only?

4-run test:  body(real,A) ^ body(zero,A) == body(real,B) ^ body(zero,B)
iff K depends only on the region words (not on claims).
Plus single-bit-flip propagation probes on the 6 live words.
"""
import time, sys, json, struct
from concurrent.futures import ProcessPoolExecutor
sys.path.insert(0, '.')
import mint_pipeline as M

rows = json.load(open('all_signings.json', encoding='utf-8'))
pairs = {r['i']: r for r in json.load(open('pair_h3.json', encoding='utf-8'))}
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
SEC = int(pairs[7]['second'])


def mk(cl, d0, d2, d4):
    by = {0: (36, 0, d0), 2: (1, 0, d2), 4: (8, 0, d4), 9: (5, 0, D9),
          8: (4, 0, D8), 7: (1, 0, struct.pack('>I', len(cl))),
          10: (len(cl) // 4, 0, cl),
          5: (1, 0, struct.pack('>I', 0)), 6: (1, 0, struct.pack('>I', 0)),
          1: (0, 0, b''), 3: (0, 0, b'')}
    return [by[i] for i in M.VA_ORDER]


def job(a):
    tag, cl, reg = a
    d0, d2, d4 = reg
    b, _ = M.finex_mint(mk(cl, d0, d2, d4), SEC, max_steps=60_000_000)
    return tag, list(struct.unpack('>48I', b))


def main():
    r = rows[7]
    clA = bytes.fromhex(r['d10'])
    clB = clA + b'\x00\x00\x00\x00'
    clC = bytes.fromhex(r['d10'][:40])          # shorter
    d0 = bytes.fromhex(r['d0']); d2 = bytes.fromhex(r['d2']); d4 = bytes.fromhex(r['d4'])
    z0, z2, z4 = b'\x00' * 144, b'\x00' * 4, b'\x00' * 32
    jobs = [('realA', clA, (d0, d2, d4)), ('zeroA', clA, (z0, z2, z4)),
            ('realB', clB, (d0, d2, d4)), ('zeroB', clB, (z0, z2, z4)),
            ('realC', clC, (d0, d2, d4)), ('zeroC', clC, (z0, z2, z4))]
    t = time.time()
    with ProcessPoolExecutor(max_workers=6) as p:
        res = dict(p.map(job, jobs))
    print('runs %.0fs' % (time.time() - t))
    D = {}
    for X, Y in (('A', 'A'), ('B', 'B'), ('C', 'C')):
        d = [a ^ b for a, b in zip(res['real' + X][4:], res['zero' + X][4:])]
        D[X] = d
        print('%s d(real^zero)  ' % X, ' '.join('%08x' % v for v in d))
    print('A==B keystream:', D['A'] == D['B'])
    print('A==C keystream:', D['A'] == D['C'])
    cap = bytes.fromhex(pairs[7]['blob'])
    print('realA matches capture:', bytes(struct.pack('>48I', *res['realA'])) == cap)
    json.dump({k: v for k, v in res.items()}, open('_p2.json', 'w'))


main()
