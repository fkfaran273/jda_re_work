# order_law.py - desc10 emission order vs the GOLDEN signing's OWN map_order
# pairing: fin_descs.json desc10 <-> wh4_records.json sign_input[7] (nsign 5595c3c4,
# created_at 2026-09-12T21:15:11.678Z+0200) - the pairing order_check2 lacked.
import json, re, itertools

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))
D = json.load(open(REV + r'\fin_descs.json', encoding='utf-8'))
d10 = bytes.fromhex([d for d in D['descs'] if d['build_idx'] == 10][0]['data_hex']).decode('latin1')
print('desc10 len:', len(d10))

gi = W['golden_sign_input_idx']
si = W['sign_inputs'][gi]
tostr, order = si['toString'], si['order']
print('golden sign_input idx:', gi, 'order present:', bool(order))

fields = []
for part in order.split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        fields.append((k, v))
print('golden map fields:', len(fields))
idx = {k: i for i, (k, _) in enumerate(fields)}
val = dict(fields)

OBS = [(0, 'adj_verification', 28), (28, 'android_uuid', 36), (64, 'api_level', 2),
       (66, 'app_token', 12), (78, 'app_version', 6), (84, 'created_at', 29),
       (113, 'device_name', 8), (121, 'device_type', 5), (126, 'environment', 10),
       (136, 'gps_adid', 36), (172, 'gps_adid_src', 7), (179, 'hardware_name', 14),
       (193, 'VEND1', 19), (212, 'installed_at', 29), (241, 'os_build', 14),
       (255, 'os_name', 7), (262, 'os_version', 2), (264, 'package_name', 13),
       (277, 'adj_signing_id', 7), (284, 'ONE1', 1), (285, 'VEND2', 19), (304, 'ONE2', 1),
       (305, 'updated_at', 29), (334, 'activity_kind', 7), (341, 'client_sdk', 12),
       (353, 'headers_id', 2), (355, 'native_version', 5)]

# 1. value/length verification against the map
bad = 0
for st, k, ln in OBS:
    if k in val:
        if len(val[k]) != ln:
            print('LEN MISMATCH', k, len(val[k]), '!=', ln); bad += 1
        elif d10[st:st + ln] != val[k]:
            print('VAL MISMATCH', k, repr(d10[st:st + ln]), 'vs', repr(val[k])); bad += 1
    else:
        print('ABSENT from map:', k); bad += 1
print('fixed-name verification issues:', bad)
print('installed_at in map:', 'installed_at' in val, '| value:', repr(val.get('installed_at')))

ONES = [k for k, v in fields if v == '1']
VENDS = [k for k, v in fields if v == 'com.android.vending']
print("1-valued fields (%d):" % len(ONES), ONES)
print("vending-valued fields:", VENDS)

# 2. monotonic-subset test with all ONE/VEND assignments
sols = []
for o1, o2 in itertools.permutations(ONES, 2):
    for v1, v2 in itertools.permutations(VENDS, 2):
        CAND = {'ONE1': [o1], 'ONE2': [o2], 'VEND1': [v1], 'VEND2': [v2]}
        seq = []
        ok = True
        for st, k, ln in OBS:
            c = CAND.get(k, [k])
            ii = [idx[x] for x in c if x in idx]
            if not ii:
                ok = False; break
            seq.append(min(ii))
        if ok and all(seq[i] < seq[i + 1] for i in range(len(seq) - 1)):
            sols.append((o1, o2, v1, v2, seq))
print('=== monotonic-subset solutions: %d ===' % len(sols))
for s in sols[:8]:
    print('  ONE1=%-22s ONE2=%-22s VEND1=%-24s VEND2=%s' % s[:4])
    print('   idx seq:', s[4])
if not sols:
    CAND = {'ONE1': ['gps_adid_attempt'], 'ONE2': ['session_count'],
            'VEND1': ['store_name_from_system'], 'VEND2': ['initiating_package_name']}
    seq = []
    for st, k, ln in OBS:
        c = CAND.get(k, [k])
        ii = [idx[x] for x in c if x in idx]
        seq.append(min(ii) if ii else -1)
    prev = -1
    for (st, k, ln), s in zip(OBS, seq):
        mk = '  <BREAK' if s < prev else ''
        print('%4d %-22s idx=%s%s' % (st, k, s, mk))
        prev = max(prev, s)

# 3. which map fields are omitted from desc10
emitted = {k for _, k, _ in OBS if k in val} | {'ONE1', 'ONE2', 'VEND1', 'VEND2'}
omitted = [k for k, _ in fields if k not in emitted]
print('omitted from desc10 (%d):' % len(omitted))
print(' ', omitted)

# 4. canonical record vs toString mismatch (flagged by parser)
canon = [c['text'] for c in W['canonicals'] if '2026-09-12T21:15:11.678Z' in c['text']]
if canon:
    c = canon[0]
    n = min(len(c), len(tostr))
    p = 0
    while p < n and c[p] == tostr[p]:
        p += 1
    print('canonical vs toString: lens %d/%d, common prefix %d' % (len(c), len(tostr), p))
    print('  canon  @p:', repr(c[max(0, p - 40):p + 60]))
    print('  tostr  @p:', repr(tostr[max(0, p - 40):p + 60]))
