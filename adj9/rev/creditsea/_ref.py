"""_ref.py — the genuine creditsea device: its GAID, and did it earn non-organic?"""
import re
b = open('adj9_cap_fresh.log', 'rb').read().decode('utf-8', 'replace')
for m in re.finditer(r'map_toString=\{', b):
    seg = b[m.end():m.end()+6000]; end = seg.find('}'); raw = seg[:end]
    k = re.search(r'activity_kind=([^,]*)', raw)
    d = dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
    k = k.group(1) if k else '?'
    if k == 'session':
        print('GENUINE creditsea device session:')
        for f in ('gps_adid', 'android_uuid', 'app_token', 'app_version',
                  'package_name', 'referrer', 'install_referrer'):
            if f in d: print('   %-20s = %s' % (f, d[f]))
        break
print()
gaids = sorted(set(re.findall(r'gps_adid=([0-9a-f-]{36})', b)))
print('GAIDs in the genuine capture:', gaids)
# any attribution payload captured?
for m in re.finditer(r'tracker_token["\s:=]+([A-Za-z0-9]+)', b):
    print('   captured tracker_token:', m.group(1))
