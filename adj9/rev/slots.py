# slots.py - what captured slots does adj9_material.json carry?
import json
import os

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
M = json.load(open(os.path.join(REV, 'adj9_material.json'), encoding='utf-8'))
print('va_order:', M['va_order'])
print('slots present:', sorted(int(k) for k in M['slots']))
for k in sorted(M['slots'], key=lambda x: int(x)):
    v = M['slots'][k]
    print('  slot %-3s len_dw=%-3s %s' % (k, v['len_dw'], v['data_hex'][:48]))
print('claims_base len:', len(M['claims_base_hex']) // 2, 'B')
print('claims_fields:', len(M['claims_fields']))
