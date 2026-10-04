import sys, struct, json
sys.path.insert(0, '.')
from concurrent.futures import ProcessPoolExecutor
import mint_pipeline as M
from _g12 import base_dmap, patch_region, SEC
from _z8lib import mint_body

A = json.load(open('all_signings.json'))
P = json.load(open('pair_h3.json'))
d0 = base_dmap('s1')
r4 = {bi: bytes.fromhex(A[4].get('d%d' % bi, '')) for bi in M.VA_ORDER}
ZW144, Z, ZW32 = bytes(144), bytes(4), bytes(32)


def z(d):
    e = dict(d)
    e[0] = ZW144
    e[2] = Z
    e[4] = ZW32
    return e


def ff(d):
    return patch_region(d, (1 << 256) - 1)


def go(a):
    n, d, s = a
    b, err = mint_body(d, s)
    return n, b


jobs = [('gold_zero', z(d0), SEC['s1']), ('gold_ff', ff(d0), SEC['s1']),
        ('gold_real', d0, SEC['s1']),
        ('row4_zero', z(r4), int(P[4]['second'])),
        ('row4_ff', ff(r4), int(P[4]['second'])),
        ('row4_real', r4, int(P[4]['second']))]
if __name__ == '__main__':
    with ProcessPoolExecutor(max_workers=6) as ex:
        res = list(ex.map(go, jobs))
    tgt = list(struct.unpack('>44I', bytes.fromhex(P[4]['blob'])[16:]))
    for (n, _, _), (_, b) in zip(jobs, res):
        print('%-10s' % n, ['%08x' % x for x in b[:6]] if b else 'FAIL',
              'EQ_ZERO=%s' % (b == res[0][1]))
    print('row4 target', ['%08x' % x for x in tgt[:6]])
