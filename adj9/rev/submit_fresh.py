import base64
import json
import urllib.parse
import urllib.request

f = json.load(open("fresh_sig.json"))
blob = bytes.fromhex(f["blob_hex"])
sig_b64 = base64.b64encode(blob).decode()
params = dict(f["params"])
url = "https://app.adjust.com/session"
auth = ('signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig_b64)
data = urllib.parse.urlencode(params).encode()
req = urllib.request.Request(url, data=data, method="POST")
req.add_header("Authorization", auth)
req.add_header("Content-Type", "application/x-www-form-urlencoded")
req.add_header("Client-SDK", "android5.7.0")
req.add_header("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)")
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print("SUBMIT:", r.status)
        print(r.read()[:300])
except Exception as e:
    print("SUBMIT FAILED:", e)
    try:
        print(e.read()[:300])
    except Exception:
        pass
