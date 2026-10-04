# verify_forge_fold.py - assert adj9_forge.build_desc10 == the proven law on
# BOTH device captures (session golden 360 B + click 387 B).
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F

# --- session golden map (wh4 si[7], same pairing as desc10_law.self_test) ---
W = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
FJ = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
d10 = bytes.fromhex([d for d in FJ['descs'] if d['build_idx'] == 10][0]['data_hex'])
si = W['sign_inputs'][W['golden_sign_input_idx']]
sval = {}
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        sval[k] = v
got_s = F.build_desc10(sval, 'session')
print('forge session: %d B %s' % (len(got_s), 'BYTE-EXACT' if got_s == d10 else 'FAIL'))

# --- click map (wh4.log line 286234, same parse as desc10_law.self_test) ---
with open(os.path.join(os.path.dirname(HERE), 'device', 'adj9_wh4.log'),
          encoding='utf-8', errors='replace') as f:
    for ln, line in enumerate(f, 1):
        if ln == 286234:
            m = re.search(r'\{(.*)\}', line.strip())
            cval = dict(re.findall(
                r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*), ?', m.group(1) + ','))
            break
cval.setdefault('adj_signing_id', '1500000')
cval.setdefault('headers_id', '10')
cval.setdefault('native_version', '5.0.0')
click = json.load(open(os.path.join(HERE, 'desc10_runs.json'),
                       encoding='utf-8'))['click']
got_c = F.build_desc10(cval, 'click')
# the forge wrapper returns BYTES (slot-10 payload); reference json is str
print('forge click:   %d B %s'
      % (len(got_c), 'BYTE-EXACT' if got_c == click.encode('latin1') else 'FAIL'))
ok_c = got_c == click.encode('latin1')

# --- missing-key contract ---
try:
    F.build_desc10({'os_name': 'android'}, 'session')
    print('missing-key contract: FAIL (no raise)')
except KeyError as e:
    print('missing-key contract: OK (raises, %d keys listed)'
          % len(str(e).split('[')[1].split(']')[0].split(',')))

print('ALL:', 'PASS' if got_s == d10 and ok_c else 'FAIL')
sys.exit(0 if got_s == d10 and ok_c else 1)
