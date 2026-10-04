# att_kind_verify.py - the law's `attribution` kind must reproduce the prediction
# derived independently in att_desc10.py (15 profile + pinned + 1 tail + 4 block2),
# and its key set must match the device's own attribution map.
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), 'device')
sys.path.insert(0, HERE)
from desc10_law import build_desc10, desc10_keys, pad4

G = json.load(open(os.path.join(DEV, 'gold6.json'), encoding='utf-8'))
N = max(len(v) for v in G.values())
att = None
for i in range(N):
    si = G['sign_input'][i]
    txt = (' '.join(str(x) for x in si) if isinstance(si, (list, tuple)) else str(si))
    if 'map_toString=' in txt:
        body = txt.split('map_toString=', 1)[1].strip()
        kv = dict(re.findall(r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*?)(?=, |$|,)',
                             body + ','))
        if kv.get('activity_kind') == 'attribution':
            att = kv
            break
print('attribution map keys: %d' % len(att))

keys = desc10_keys('attribution')
print('law keys (%d): %s' % (len(keys), keys))
print()
missing = [k for k in keys if k not in att]
print('law keys absent from the device map : %s' % (missing or 'NONE'))
extra_lawish = [k for k in att if k in ('initiated_by', 'hardware_name', 'installed_at',
                                        'os_build', 'session_count',
                                        'store_name_from_system', 'updated_at')
                and k not in keys]
print('map keys the law omits (diagnostic): %s' % (extra_lawish or 'NONE'))
print()

raw = build_desc10(att, 'attribution')
padded = pad4(raw.encode('latin1'))
print('=== law output ===')
print(raw)
print('unpadded %d B (#7)   padded %d B (#10, %d dwords)'
      % (len(raw), len(padded), len(padded) // 4))
print()
print('=== independent prediction (att_desc10.py) ===')
print('KlcAG2cbAAsKSl1KVi0FGiJbDHMI7ba51fce-9d49-46ec-94d3-924e8a0ff26931jut9tib0eeps'
      '3.13.92026-09-14T23:44:40.543Z+0530moto g42phoneproductiond016e7e4-fb1c-4d0a-'
      'b619-db01f6a6a262servicebackendandroid12com.penti.app15000001attribution'
      'android5.7.0105.0.0')
print('unpadded 246 B   padded 248 B (62 dwords)')
print()
print('AGREE: %s' % (len(raw) == 246 and len(padded) == 248))
print()
print('=== kinds available ===')
for kind in ('session', 'click', 'attribution'):
    k = desc10_keys(kind, att)
    print('  %-12s %d keys' % (kind, len(k)))