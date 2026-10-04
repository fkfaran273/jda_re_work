# probe_a.py - ground truth: fin_descs layout + desc_det.log content
import json
import os

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
F = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
print('fin_descs keys:', list(F.keys()))
print('va_order:', F.get('va_order'))
print('target:', {k: v for k, v in F['target'].items() if k != 'blob_hex'})
print()
for i, d in enumerate(F['descs']):
    dh = d.get('data_hex') or ''
    print('  idx %2d build_idx %-3s len_dw %-5s bytes %-4d %s'
          % (i, d.get('build_idx'), d.get('len_dw'), len(dh) // 2, dh[:64]))
print()
print('=== desc_det.log ===')
p = os.path.join(REV, 'desc_det.log')
if os.path.exists(p):
    print(open(p, encoding='utf-8', errors='replace').read())
else:
    print('(missing)')
