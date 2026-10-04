# query_audit.py - OFFLINE audit: the minted4 map is the exact map the DEVICE
# signed. Compare it against the query send_mint4.py actually put on the wire.
# Any key the native signed but we never sent = a guaranteed message mismatch if
# the server rebuilds the signature message from the received request.
import ast
import json
import os
import re

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
import sys
sys.path.insert(0, REV)
import desc10_law as L

M = json.load(open(os.path.join(REV, 'minted4.json'), encoding='utf-8'))
pairs = M['mapPairs']
mp = {}
for k, v in pairs:
    mp.setdefault(k, v)
print('minted map keys: %d' % len(mp))

# what send_mint4.py actually sent: parse the q dict out of the source
src = open(os.path.join(REV, 'send_mint4.py'), encoding='utf-8').read()
i = src.index('q = {')
j = src.index('}', i)
sent = set(re.findall(r'"([a-z_0-9]+)"\s*:', src[i:j + 1]))
print('sent query keys : %d' % len(sent))

for kind in ('session', 'click'):
    keys = L.desc10_keys(kind)
    signed = [k for k in keys if k in mp]
    missing_from_map = [k for k in keys if k not in mp]
    print('\n--- law keys for %s: %d' % (kind, len(keys)))
    print('  present in signed map : %d' % len(signed))
    print('  absent from signed map: %s' % (missing_from_map or 'none'))
    not_sent = [k for k in signed if k not in sent]
    print('  SIGNED BUT NOT SENT    : %s' % (not_sent or 'none'))
    extra = [k for k in sent if k not in keys]
    print('  sent but not in law    : %s' % (extra or 'none'))

# also: which map keys were dropped by val.setdefault (duplicates)?
dups = {}
for k, v in pairs:
    dups.setdefault(k, []).append(v)
print('\nduplicate map keys (first wins in our sender):')
for k, vs in dups.items():
    if len(vs) > 1:
        print('  %s -> %s' % (k, vs))
