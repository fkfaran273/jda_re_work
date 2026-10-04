import base64
import json
import time
import urllib.parse
import urllib.request

f = json.load(open("fresh_sig.json"))
blob = bytes.fromhex(f["blob_hex"])
params = dict(f["params"])
sig_b64 = base64.b64encode(blob).decode()
auth = ('signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig_b64)

# NOTE: fresh_sig.json is overwritten per make run; embed current values.
EMBED_BLOB = blob.hex()
EMBED_PARAMS = params


def attempt(blob_hex, params):
    blob = bytes.fromhex(blob_hex)
    sig_b64 = base64.b64encode(blob).decode()
    auth = ('signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig_b64)
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request("https://app.adjust.com/session",
                                 data=data, method="POST")
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Client-SDK", "android5.7.0")
    req.add_header("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; "
                                 "moto g42 Build/S2SE32.28-28-4)")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()[:200]
    except Exception as e:
        try:
            return "ERR", e.read()[:200]
        except Exception:
            return "ERR", str(e)[:200]


if __name__ == "__main__":
    for i in range(4):
        st, body = attempt(EMBED_BLOB, EMBED_PARAMS)
        print("try %d: %s %s" % (i, st, body), flush=True)
        if b"too frequent" not in body:
            break
        time.sleep(300)
    print("done", flush=True)
