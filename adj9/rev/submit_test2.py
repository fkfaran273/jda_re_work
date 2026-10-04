import json
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
auth = s["authorization"].split("\r")[0]
data = urllib.parse.urlencode(params).encode()
req = urllib.request.Request(url, data=data, method="POST")
req.add_header("Authorization", auth)
req.add_header("Content-Type", "application/x-www-form-urlencoded")
req.add_header("User-Agent", "Adjust/5.7.0 (android)")
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print("fresh-ts + old-blob:", r.status)
        print(r.read()[:300])
except Exception as e:
    print("fresh-ts + old-blob FAILED:", e)
