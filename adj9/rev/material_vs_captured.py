# material_vs_captured.py - WHY does the law path take a different VM path than
# the CONTROL recipe (68.6 s / 9.87M steps -> 48/48 BYTE-EXACT)?
# Compare every captured descriptor in fin_descs.json against adj9_material.json.
import json
import os

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
F = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
M = json.load(open(os.path.join(REV, 'adj9_material.json'), encoding='utf-8'))
D = {d['build_idx']: (d['len_dw'], d['data_hex']) for d in F['descs']}
S = {int(k): (v['len_dw'], v['data_hex']) for k, v in M['slots'].items()}
print('fin_descs idx:', sorted(D))
print('material idx :', sorted(S))
print()
for i in sorted(set(D) | set(S)):
    a = D.get(i)
    b = S.get(i)
    if a is None:
        print('  #%d  only in MATERIAL  len_dw=%s %s' % (i, b[0], b[1][:40]))
    elif b is None:
        print('  #%d  only in CAPTURED  len_dw=%s %s' % (i, a[0], a[1][:40]))
    else:
        same = (a[0] == b[0]) and (a[1] == b[1])
        print('  #%d  %s  captured(len_dw=%s,%dB) material(len_dw=%s,%dB)'
              % (i, 'SAME' if same else '*** DIFFERENT ***',
                 a[0], len(a[1]) // 2, b[0], len(b[1]) // 2))
        if not same:
            print('       captured: %s' % a[1][:64])
            print('       material: %s' % b[1][:64])
print()
print('captured #9 (5 dw):', D[9][1] if 9 in D else '-')
print('material #9 (5 dw):', S[9][1] if 9 in S else '-')
