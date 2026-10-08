import json, re, sys
from datetime import datetime, timezone, timedelta
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
    blob = bytes.fromhex(m.group(1))
    ca = re.search(r'created_at["\']?:\s*["\']?([^"\'&,}]+)',
                   str(e['body'])) or re.search(r'created_at=([^&]+)', e['url'])
    if not ca:
        continue
    t = ca.group(1).replace('%3A', ':').replace('%2B', '+').replace('Z+0530', '').replace('Z', '')
    try:
        dt = datetime.strptime(t.split('.')[0], '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        print(e['sid'], 'bad time', ca.group(1)); continue
    # local +0530 -> utc epoch
    base = int((dt - timedelta(hours=5, minutes=30)).replace(tzinfo=timezone.utc).timestamp())
    hit = [off for off in range(-90, 91)
           if sg.make_header(base + off) == blob[:16]]
    print(e['sid'], e['url'].split('?')[0].split('/')[-1], 'base_epoch', base,
          'header-law hit:', hit)
