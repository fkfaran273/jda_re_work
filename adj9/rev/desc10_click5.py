# desc10_click5.py - find the click record's OWN map: scan all wh4 sign_inputs for
# android_uuid d773f47f / created_at 21:15:11.762 / kind click; dump key sets and
# check which of them contain the click-only keys (foreground/referrer/...).
import json, re

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))

def fields_of(si):
    out = []
    for part in si['order'].split('\x02'):
        if '\x01' in part:
            k, v = part.split('\x01', 1)
            out.append((k, v))
    return out

print('=== all %d sign_inputs ===' % len(W['sign_inputs']))
for i, si in enumerate(W['sign_inputs']):
    fl = fields_of(si)
    val = dict(fl)
    keys = [k for k, _ in fl]
    print('si[%d] nfields=%2d au=%s ak=%-9s created_at=%s' % (
        i, len(fl), val.get('android_uuid', '?')[:8],
        val.get('activity_kind', '?'), val.get('created_at', '?')))
    print('      order:', ' '.join(keys))

# does ANY captured map contain the click-only keys?
for key in ('foreground', 'referrer', 'referrer_api', 'source', 'session_count'):
    have = [i for i, si in enumerate(W['sign_inputs'])
            if any(k == key for k, _ in fields_of(si))]
    print('key %-16s present in si:' % key, have)

# golden si[7]: which of the click-only keys does it have / miss?
gold = W['sign_inputs'][W['golden_sign_input_idx']]
gk = {k for k, _ in fields_of(gold)}
print()
print('golden si[7] keys missing click-extras:',
      [k for k in ('foreground', 'referrer', 'referrer_api', 'source') if k not in gk])
print('golden si[7] full key list:', sorted(gk))
print('golden map: initiating_package_name=%r store_name_from_system=%r' % (
    dict(fields_of(gold)).get('initiating_package_name'),
    dict(fields_of(gold)).get('store_name_from_system')))
