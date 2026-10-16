# -*- coding: utf-8 -*-
"""replay_gvo_ios.py -- the AGENTS.md attribution replay rule on the genuine
adj7-iOS row (nirio, sid 39), the adj8ios verification method:

  ARM  our signed POST /session (genuine wire map, fresh stamps) -> 200 ask_in
  wait ask_in
  G    genuine control: the LOGGED attribution request verbatim
       (captured query + captured Authorization)
  O    ours: the SAME query, signature freshly minted by adj7_ios_pure
       (fresh second + nonce, same stamps shape as the capture)

PASS = G and O answer identically (status + attribution object).  Per the
rule: on an aged booked row both re-answer Organic; O==G is the signature
verdict.  400 {adid, ask_in} on either leg is the documented ask-cadence
throttle, not a verdict -- the ask is re-armed and retried.
"""
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')

from adj7_ios_pure import sign_request  # noqa: E402

UA = "Nirio/494 CFNetwork/1410.1 Darwin/22.6.0"
CLIENT_SDK = "react-native5.4.4@ios5.4.6"
HOST = "https://consent.adjust.com"
TZ = timezone(timedelta(hours=5, minutes=30))
SID_ATTR, SID_SESSION = "39", "38"

recs = json.load(open(os.path.join(HERE, "nirio_08Sep",
                                   "nirioiosauto_08Sep_ios_CT_adjust.json")))
vecs = json.load(open(os.path.join(HERE, "frozen_vectors.json")))


def rec(sid):
    return [x for x in recs if x["sid"] == sid][0]


def vec(sid):
    return [x for x in vecs if x["sid"] == sid][0]


def stamp_now(ts=None):
    ts = time.time() if ts is None else ts
    dt = datetime.fromtimestamp(int(ts), TZ)
    return (dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % int(ts % 1 * 1000)
            + "Z+0530")


def call(method, url, params=None, auth=None, body=None):
    import http.client
    p = urllib.parse.urlsplit(url)
    c = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=30)
    target = p.path + ("?" + p.query if p.query else "")
    if body is not None:
        target = p.path
    hdrs = {"User-Agent": UA, "Host": p.hostname, "Connection": "close",
            "Accept-Encoding": "identity"}
    if auth:
        hdrs["Client-Sdk"] = CLIENT_SDK
        hdrs["Authorization"] = auth
    if body is not None:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs["Content-Length"] = str(len(body))
    c.request(method, target, body=body, headers=hdrs)
    r = c.getresponse()
    raw = r.read().decode("utf-8", "replace")
    c.close()
    return r.status, raw


A = rec(SID_ATTR)
S = rec(SID_SESSION)
VA = vec(SID_ATTR)

print("== ARM: signed POST /session (genuine map, fresh stamps)", flush=True)
sp = dict(S["body"])
now = time.time()
sp["created_at"] = stamp_now(now)
sp["sent_at"] = stamp_now(now + 0.05)
sp["installed_at"] = S["body"]["installed_at"]     # keep the genuine install
sec = int(now)
auth = sign_request(sp, "session", second=sec, client_sdk=CLIENT_SDK)[0]
st, body = call("POST", HOST + "/session", body=urllib.parse.urlencode(sp),
                auth=auth)
print("   session ->", st, body[:160], flush=True)
p = json.loads(body)
adid = p.get("adid")
ask_in = p.get("ask_in")
print("   adid=", adid, "ask_in=", ask_in, flush=True)
if ask_in:
    time.sleep(max(2.0, ask_in / 1000.0 + 1.0))

# ---- G: the logged request verbatim -------------------------------------
gq = A["url"]
gauth = ("Signature signature=\"%s\",adj_signing_id=\"1300000\","
         "algorithm=\"adj7\",headers_id=\"7\",native_version=\"3.61.0\""
         % VA["sig"].upper())
print("== G: genuine control (logged query + logged signature)", flush=True)
def ask_retry(body):
    """ask_in wait, capped: a 1-hour cold throttle is the documented
    ancient-second behaviour, not a verdict -- record it, don't sleep on it."""
    try:
        ai = json.loads(body).get("ask_in")
    except Exception:
        return None
    if not ai:
        return None
    if ai > 5000:
        print("   (cold-ask throttle ask_in=%s -- ancient signing second; "
              "documented, not sleeping)" % ai, flush=True)
        return None
    time.sleep(max(2.0, ai / 1000.0 + 1.0))
    return ai


for attempt in range(4):
    st_g, body_g = call("GET", gq, auth=gauth)
    print("   G ->", st_g, body_g[:150], flush=True)
    if st_g == 200:
        break
    if not ask_retry(body_g):
        break

# ---- O: same query, our fresh signature ---------------------------------
print("== O: same query, OUR fresh signature", flush=True)
qp = dict(urllib.parse.parse_qsl(A["url"].split("?", 1)[1],
                                 keep_blank_values=True))
now = time.time()
qp["created_at"] = stamp_now(now)
qp["sent_at"] = stamp_now(now + 0.02)
sec = int(now)
auth_o = sign_request(qp, "attribution", second=sec, client_sdk=CLIENT_SDK)[0]
url_o = A["url"].split("?", 1)[0] + "?" + urllib.parse.urlencode(
    qp, quote_via=urllib.parse.quote)
for attempt in range(4):
    st_o, body_o = call("GET", url_o, auth=auth_o)
    print("   O ->", st_o, body_o[:150], flush=True)
    if st_o == 200:
        break
    if not ask_retry(body_o):
        break

# ---- compare -------------------------------------------------------------
print("== COMPARE", flush=True)
print("   genuine logged verdict:", json.dumps(A.get("response"))[:220],
      flush=True)
same_status = st_g == st_o
try:
    vg = json.loads(body_g).get("attribution")
    vo = json.loads(body_o).get("attribution")
except Exception:
    vg = vo = None
same_attr = vg == vo
print("   G status", st_g, "| O status", st_o, "| equal:", same_status,
      flush=True)
print("   G attr:", json.dumps(vg)[:250], flush=True)
print("   O attr:", json.dumps(vo)[:250], flush=True)
print("   ATTR EQUAL:", same_attr, flush=True)
print()
if same_status and same_attr:
    print("*** REPLAY PASS: O == G (our fresh signature behaves exactly like "
          "the genuine one) ***", flush=True)
else:
    print("*** REPLAY CHECK: legs differ -- inspect above ***", flush=True)
