# desc10_click8.py - dump ALL values of si[1] (click map, other device) and si[7]
# (golden session) so the two '10' tokens in the golden click's r..u block can be
# identified by key name; then partition-search for a byte-exact 4-run law.
import json

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))

def fields_of(si):
    out = []
    for part in si['order'].split('\x02'):
        if '\x01' in part:
            k, v = part.split('\x01', 1)
            out.append((k, v))
    return out

for idx in (1, 7):
    print('===== si[%d] =====' % idx)
    for k, v in sorted(fields_of(W['sign_inputs'][idx])):
        print('  %-26s %r' % (k, v))
    print()

# which keys anywhere hold value '10' / '0' / '1'?
for target in ('10', '0', '1', '1500000'):
    ks = {}
    for si in W['sign_inputs']:
        for k, v in fields_of(si):
            if v == target:
                ks.setdefault(k, 0)
                ks[k] += 1
    print('value %-8r keys: %s' % (target, sorted(ks)))
