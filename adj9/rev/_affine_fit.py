import json, struct, sys
rows = json.load(open('all_signings.json'))
ph3  = json.load(open('pair_h3.json'))
USE  = [0,1,3,4,5,6,7]          # row2 excluded (blob dup of row4)
def dw(h): return list(struct.unpack('>%dI'%(len(h)//8), bytes.fromhex(h)))
recs = []
for i in USE:
    r = rows[i]; p = ph3[i]
    b = bytes.fromhex(p['blob'])
    body = [struct.unpack_from('>I', b, 4*j)[0] for j in range(4,48)]
    hdr  = [struct.unpack_from('>I', b, 4*j)[0] for j in range(4)]
    src = {}
    src['d0'] = dw(r['d0']); src['d2'] = [int(r['d2'],16)]; src['d4'] = dw(r['d4'])
    src['d7'] = [int(r['d7'],16)]; src['d8'] = dw(r['d8']); src['d9'] = dw(r['d9'])
    cl = bytes.fromhex(r['d10']); cw = dw(cl.hex())
    src['claims'] = cw
    src['hdr'] = hdr
    recs.append((body, src))
N = len(recs)
M = 1<<32
hits = []
for j in range(44):
    B = [rc[0][j] for rc in recs]
    for name in ('d0','d2','d4','d7','d8','d9','claims','hdr'):
        V = [rc[1][name] for rc in recs]
        n = min(len(v) for v in V)
        for k in range(n):
            X = [v[k] for v in V]
            # (a) y = x + c
            cs = {(B[t]-X[t]) % M for t in range(N)}
            if len(cs) == 1:
                hits.append((j, '%s[%d]'%(name,k), 'add', cs.pop())); continue
            # (b) y = x ^ c
            cs = {B[t]^X[t] for t in range(N)}
            if len(cs) == 1:
                hits.append((j, '%s[%d]'%(name,k), 'xor', cs.pop())); continue
            # (c) y = a*x + c  (solve from rows 0,1)
            dx = (X[1]-X[0]) % M
            if dx % 2 == 1:
                a = ((B[1]-B[0]) * pow(dx, -1, M)) % M
                c = (B[0] - a*X[0]) % M
                if all((a*X[t] + c) % M == B[t] for t in range(N)):
                    hits.append((j, '%s[%d]'%(name,k), 'muladd', (a, c))); continue
            # (d) y = (a*x) ^ c
            if dx % 2 == 1:
                a = ((B[1]^B[0]) * pow(dx, -1, M)) % M
                c = B[0] ^ (a*X[0] % M)
                if all(((a*X[t]) % M) ^ c == B[t] for t in range(N)):
                    hits.append((j, '%s[%d]'%(name,k), 'mulxor', (a, c))); continue
print('per-word affine hits:', len(hits))
for h in hits[:80]: print('  body[%2d] <- %-12s %-7s %s' % (h[0], h[1], h[2], hex(h[3]) if isinstance(h[3],int) else [hex(x) for x in h[3]]))
