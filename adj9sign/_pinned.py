"""_pinned.py — the PINNED/app constants in the GENUINE creditsea signing map
vs what we send (penti-derived)."""
import re
CAP = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea\adj9_cap_fresh.log'
b = open(CAP, 'rb').read().decode('utf-8', 'replace')
gen = {}
for m in re.finditer(r'map_toString=\{', b):
    seg = b[m.end():m.end()+6000]; end = seg.find('}'); raw = seg[:end]
    k = re.search(r'activity_kind=([^,]*)', raw); k = k.group(1) if k else '?'
    d = dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
    gen.setdefault(k, d)
PIN = ['adj_verification', 'adj_signing_id', 'headers_id', 'native_version',
       'algorithm', 'client_sdk', 'app_token']
OURS = {
 'adj_verification': 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
 'adj_signing_id': '1500000',
 'headers_id': '10',
 'native_version': '5.0.0',
 'algorithm': 'adj9',
 'client_sdk': 'flutter5.8.0@android5.8.0',
 'app_token': 'i2n2e5kmcpvk',
}
print('%-20s %-34s %-34s %s' % ('constant', 'GENUINE creditsea', 'OURS (penti-derived)', 'match'))
print('-'*110)
for k in PIN:
    gv = gen.get('session', {}).get(k, '<absent>')
    gv2 = gen.get('click', {}).get(k, '<absent>')
    ov = OURS[k]
    m = 'YES' if gv == ov else ('NO  <== MISMATCH' if gv != '<absent>' else '?')
    print('%-20s %-34s %-34s %s' % (k, gv[:34], ov[:34], m))
    if gv != gv2:
        print('%-20s   (click map has: %s)' % ('', gv2[:40]))
