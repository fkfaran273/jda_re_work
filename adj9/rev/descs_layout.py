# descs_layout.py - exact fin_descs descriptor layout: list index, build_idx,
# len_dw, data length, first bytes. Needed to replace the RIGHT slots.
import json
import os

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
F = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
print('descs entries:', len(F['descs']))
for i, d in enumerate(F['descs']):
    dh = d.get('data_hex') or ''
    print('  idx %2d  build_idx %-3s len_dw %-4s databytes %-4d %s'
          % (i, d.get('build_idx'), d.get('len_dw'), len(dh) // 2, dh[:40]))
print('keys of one entry:', list(F['descs'][0].keys()))
print('target keys:', list(F['target'].keys()))