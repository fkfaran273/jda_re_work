import json, struct

A = json.load(open('all_signings.json'))
D = json.load(open('det_full.json'))
rows = []
for s in A:
    rows.append(('als-'+s['d2'], struct.unpack('>36I', bytes.fromhex(s['d0']))))
for s in D:
    d2 = '%08x'%s['d2'] if isinstance(s['d2'],int) else s['d2']
    rows.append(('det-'+d2, struct.unpack('>36I', bytes.fromhex(s['d0']))))
n = len(rows)
print('n =', n)

# position -> (kind, residue)
pos_kind = {}
for i in range(36):
    r = i % 4
    if i == 0:
        pos_kind[i] = ('W0', 0)
    elif r == 0:
        pos_kind[i] = ('W1', 0)
    elif r == 1:
        pos_kind[i] = ('C1', 1)
    elif r == 2:
        pos_kind[i] = ('C2', 2)
    elif r == 3:
        pos_kind[i] = ('C3', 3)

print('\n--- within-row consistency ---')
ok_all = True
for tag, w in rows:
    by_res = {}
    for i in range(36):
        k = (pos_kind[i][0], pos_kind[i][1])
        by_res.setdefault(k, set()).add(w[i])
    bad = [k for k,v in by_res.items() if len(v)>1]
    if bad:
        ok_all = False
        print('  INCONSISTENT', tag, bad)
print('all consistent:', ok_all)

# fixed-plaintext test
print('\n--- fixed-plaintext: within-pair delta per residue ---')
pairs_ok = []
for a, wa in rows:
    for b, wb in rows:
        if a >= b: continue
        d = [wa[i] ^ wb[i] for i in range(36)]
        c1 = set([d[i] for i in range(36) if pos_kind[i][1]==1])
        c2 = set([d[i] for i in range(36) if pos_kind[i][1]==2])
        c3 = set([d[i] for i in range(36) if pos_kind[i][1]==3])
        w0w1 = set([d[i] for i in range(36) if pos_kind[i][1]==0])
        ok = (len(c1)==1 and len(c2)==1 and len(c3)==1 and len(w0w1)<=2)
        if ok:
            pairs_ok.append((a,b, d[0], list(c1)[0], list(c2)[0], list(c3)[0], list(w0w1), [i for i in range(36) if pos_kind[i][1]==0]))
print('pairs with fixed-plaintext pattern:', len(pairs_ok))
for p in pairs_ok[:5]:
    print('  ', p[0], p[1], 'dC1=%08x dC2=%08x dC3=%08x w0w1=%s'%(p[3],p[4],p[5],p[6]))

# cross-sample delta constancy (should vary per pair)
print('\n--- C1 deltas across all pairs (should vary if key varies per signing) ---')
c1_all = []
for a,wa in rows:
    for b,wb in rows:
        if a<b:
            c1_all.append(wa[1] ^ wb[1])
print('unique C1 deltas:', len(set(c1_all)), sorted(set(c1_all))[:12])

# key deltas vs golden (sample index 7 = s[7] = als-fb1a8296)
print('\n--- key deltas vs golden (s7) ---')
ref = None
for tag,w in rows:
    if tag == 'als-fb1a8296':
        ref = w
        break
if ref:
    for tag,w in rows:
        if tag == ref_tag: continue
        d = [w[i]^ref[i] for i in range(36)]
        print('  %-12s dW0=%08x dC1=%08x dC2=%08x dC3=%08x dW1=%08x'
              %(tag, d[0], d[1], d[2], d[3], d[4]))

# within-row cycle relations
print('\n--- within-row 4-cycle relations ---')
for tag,w in rows:
    C1,C2,C3,W1 = w[1],w[2],w[3],w[4]
    rels = []
    if C1^C2 == C3^W1: rels.append('C1^C2==C3^W1')
    if (C1+C2)&0xFFFFFFFF == (C3+W1)&0xFFFFFFFF: rels.append('C1+C2==C3+W1')
    if (C1+C3)&0xFFFFFFFF == (C2+W1)&0xFFFFFFFF: rels.append('C1+C3==C2+W1')
    if (C2+C3)&0xFFFFFFFF == (C1+W1)&0xFFFFFFFF: rels.append('C2+C3==C1+W1')
    # rotations
    import struct as ST
    def rol(x,n): return ((x<<n)|(x>>(32-n)))&0xFFFFFFFF
    if rol(C1,8)==C2: rels.append('rol8(C1)==C2')
    if rol(C2,8)==C3: rels.append('rol8(C2)==C3')
    if rol(C3,8)==W1: rels.append('rol8(C3)==W1')
    if rol(C1,16)==C3: rels.append('rol16(C1)==C3')
    if w[0] == (C1^C2^C3^W1): rels.append('W0==C1^C2^C3^W1')
    if w[0] == (C1+C2+C3+W1)&0xFFFFFFFF: rels.append('W0==C1+C2+C3+W1')
    print('  %-12s %s'%(tag, rels if rels else '-'))

# cross-row cycle relations (per residue)
print('\n--- cross-row cycle delta per residue (constant? if so -> key-slice vs H) ---')
for res in [1,2,3]:
    deltas = []
    for a,wa in rows:
        for b,wb in rows:
            if a<b:
                deltas.append((a,b,wa[1+res-1]^wb[1+res-1]))
    print(' residue %d: %d pairs, unique deltas %d'%(res, len(deltas), len(set(x[2] for x in deltas)))
