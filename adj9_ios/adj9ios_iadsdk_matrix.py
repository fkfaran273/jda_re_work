"""iadsdk /adserver/attribution/v3 — request matrix for the token generation call."""
import http.client, json, datetime, sys
from curl_cffi import requests as cr

HOST = "ca.iadsdk.apple.com"
PATH = "/adserver/attribution/v3"
SIGNATURE2 = open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\_sig2.txt").read().strip() \
    if __import__("os").path.exists(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\_sig2.txt") else None

if not SIGNATURE2:
    # recover from the capture
    raw = open(r"C:\Users\Apps\Downloads\pentiiosauto_ct_logs_5oct_ios11.chls", "rb").read()
    txt = raw.decode("latin-1")
    i = txt.find("X-Apple-ActionSignature2")
    # the signature value: base64-ish run after the header name
    import re
    m = re.search(r"X-Apple-ActionSignature2[.. ]*([A-Za-z0-9+/=]{500,})", txt[i:i+3000])
    SIGNATURE2 = m.group(1) if m else ""
    open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\_sig2.txt", "w").write(SIGNATURE2)
print("sig2 len:", len(SIGNATURE2))

now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
OLD_ISO = "2026-10-05T06:16:48Z"

BASE_BODY = {"callEventType": 0, "bundleId": "com.penti.PentiApp",
             "attribution": False, "readOnly": False, "adamId": "1510355381"}
KEY = "CBdNbt5lrMjV54+CGb9HItWX6Kuc65HsWvZljNMkN4Q="


def attempt(label, body, ts, ctype="application/json", h2=False, with_sig=True):
    hdrs = {"storeFront": "143480-2,29", "osBuild": "", "timestamp": ts,
            "osPlatform": "iOS", "bundleId": "com.apple.ap.promotedcontent",
            "osVersion": "",
            "User-Agent": "promotedcontentd/1.1 CFNetwork/3860.600.12 Darwin/25.5.0",
            "Accept": "*/*"}
    if with_sig:
        hdrs["X-Apple-ActionSignature2"] = SIGNATURE2
    hdrs["Content-Type"] = ctype
    if h2:
        r = cr.post("https://" + HOST + PATH, data=json.dumps(body), headers=hdrs, timeout=30)
        st, body_txt = r.status_code, r.text
    else:
        c = http.client.HTTPSConnection(HOST, 443, timeout=30)
        c.request("POST", PATH, body=json.dumps(body), headers=hdrs)
        resp = c.getresponse()
        st, body_txt = resp.status, resp.read()[:400]
        c.close()
    print(f"[{label}] {st} | {body_txt[:200]}")
    return st, body_txt


print("=== matrix (fresh timestamp unless noted) ===")
attempt("V1 no-key, fresh ts, json", dict(BASE_BODY), now_iso)
attempt("V2 no-key, OLD ts, json", dict(BASE_BODY), OLD_ISO)
attempt("V3 with-key, fresh ts, json", dict(BASE_BODY, attributionKey=KEY), now_iso)
attempt("V4 no-key, fresh ts, text/plain", dict(BASE_BODY), now_iso, ctype="text/plain")
attempt("V5 no-key, fresh ts, h2 (curl_cffi)", dict(BASE_BODY), now_iso, h2=True)
attempt("V6 attribution=true, fresh ts, h2", dict(BASE_BODY, attribution=True), now_iso, h2=True)
attempt("V7 no-sig, fresh ts, h2", dict(BASE_BODY), now_iso, h2=True, with_sig=False)