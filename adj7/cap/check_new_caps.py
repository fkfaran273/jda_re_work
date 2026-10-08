import json, re, sys
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import adj7_pure as sg
D = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json'))
for e in D:
    auth = None
    for k, v in e['request_headers']:
        if k.lower() == 'authorization':
            auth = v
    if not auth:
        continue
    m = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
    if not m:
        continue
    blob = bytes.fromhex(m.group(1))
    nv = re.search(r'native_version="([^"]+)"', auth).group(1)
    hi = re.search(r'headers_id="([^"]+)"', auth).group(1)
    print(e['sid'], e['method'], e['url'].split('?')[0])
    print('   tag_ok=', sg.verify_tag(blob), 'head=', blob[:16].hex().upper(),
          '| native', nv, 'headers_id', hi)
    # header law: try signing seconds around created_at
    ca = re.search(r'created_at=([^&]+)', e['url'])
    if ca:
        from datetime import datetime, timezone, timedelta
        ts = ca.group(1).replace('%3A', ':').replace('Z%2B0530', '').replace('+0530','')
        print('   created_at field:', ca.group(1))
