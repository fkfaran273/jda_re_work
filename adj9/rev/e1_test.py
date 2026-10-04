# e1_test.py — split the server models:
#   E1: VERBATIM genuine query + CRAFTED blob (same header-second)
#   E2: VERBATIM genuine query + VERBATIM blob (control, expect TRUE)
import json, base64, re, sys, datetime, calendar
import urllib.parse as up

sys.path.insert(0, r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
import adj9_full_chain as A

HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
fg = json.load(open(HERE + '/fresh_genuine.json'))
q = fg['query']
print('query head:', q[:90])

created = up.unquote(re.search(r'created_at=([^&]+)', q).group(1))
gps = up.unquote(re.search(r'gps_adid=([^&]+)', q).group(1))
auid = up.unquote(re.search(r'android_uuid=([^&]+)', q).group(1))
dt = datetime.datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.%fZ%z')
sec = calendar.timegm(dt.utctimetuple()) + 1   # header law: created second + 1
print('created:', created, '-> header sec:', sec)
print('gps:', gps, ' auid:', auid)

st, steps, blob = A.make_signature(sec, created.encode(), gps=gps, auid=auid)
print('mint status=%s steps=%d blob[:24]=%s' % (st, steps, base64.b64encode(blob)[:24].decode()))

u = 'https://app.adjust.com' + q
print('E1 verbatim-params + CRAFTED blob ->', A.send_proxy(u, None, blob, method='GET'))
print('E2 verbatim-params + VERBATIM blob ->',
      A.send_proxy(u, None, bytes.fromhex(fg['blob_hex']), method='GET'))
print('DONE')
