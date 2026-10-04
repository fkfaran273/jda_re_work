import json
import os
import urllib.request
import urllib.parse
import datetime

d = json.load(open("saz_sessions.json"))
s = d[0]
url = s["url"]
params = dict(s["params"])
now = datetime.datetime.now(datetime.timezone.utc)
params["created_at"] = now.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200")
params["sent_at"] = now.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200")
blob = os.urandom(192)
sig_b64 = __import__("base64").b64encode(blob).decode()
auth = ('signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig_b64)
data = urllib.parse.urlencode(params).encode()
req = urllib.request.Request(url, data=data, method="POST")
req.add_header("Authorization", auth)
req.add_header("Content-Type", "application/x-www-form-urlencoded")
req.add_header("User-Agent", "Adjust/5.7.0 (android)")
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print("garbage-sig:", r.status)
        print(r.read()[:200])
except Exception as e:
    print("garbage-sig FAILED:", e)
