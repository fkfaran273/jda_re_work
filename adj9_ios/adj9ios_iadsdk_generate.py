"""iadsdk generation call: body WITHOUT attributionKey + the captured signature."""
import http.client, json, re, datetime

body = open("_iadsdk_body.bin", "rb").read()
sig = open("_sig2.txt").read().rstrip("q")

gen = re.sub(r',?\s*"attributionKey" : "[^"]*"', "", body.decode("utf8"))
gen_b = gen.encode("utf8")
print("generation body:", gen_b[:170], "...")
print()

HOST = "ca.iadsdk.apple.com"
PATH = "/adserver/attribution/v3"


def call(body_bytes, ts, extra_note=""):
    hdrs = {"Host": HOST,
            "Content-Type": "application/json",
            "storeFront": "143480-2,29",
            "timestamp": ts,
            "osPlatform": "iOS",
            "bundleId": "com.apple.ap.promotedcontent",
            "X-Apple-ActionSignature2": sig,
            "User-Agent": "promotedcontentd/1.1 CFNetwork/3860.600.12 Darwin/25.5.0",
            "Accept": "*/*",
            "Connection": "close"}
    c = http.client.HTTPSConnection(HOST, 443, timeout=30)
    c.request("POST", PATH, body=body_bytes, headers=hdrs)
    r = c.getresponse()
    resp = r.read()
    c.close()
    print("[%s ts=%s] %d | %s" % (extra_note, ts[:19], r.status, resp[:300]))
    return r.status, resp


now_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

st, resp = call(gen_b, "2026-10-05T06:16:48Z", "GEN captured-ts")
if st == 200 and resp:
    try:
        print("*** ATTRIBUTIONKEY:", json.loads(resp).get("attributionKey"))
    except Exception:
        pass
st, resp = call(gen_b, now_ts, "GEN fresh-ts")
if st == 200 and resp:
    try:
        print("*** ATTRIBUTIONKEY:", json.loads(resp).get("attributionKey"))
    except Exception:
        pass
st, resp = call(gen_b.replace('"callEventType" : 0', '"callEventType" : 1'),
                now_ts, "GEN callEventType=1")
if st == 200 and resp:
    print("*** RESP:", resp[:200])
st, resp = call(gen_b.replace('"attribution" : false', '"attribution" : true'),
                now_ts, "GEN attribution=true")
if st == 200 and resp:
    print("*** RESP:", resp[:200])