"""replay_attr_test.py — the adj9-ios "replay rule" test for adj8-iOS.

Takes the genuine exchange out of wave_19may_install_newapp_ios8.chls (the
verified /session, /sdk_click and /attribution requests plus the responses
Adjust actually returned), then re-sends them through OUR signature and compares.

  1. /session      -> same adid as the log?
  2. /sdk_click    -> same adid as the log?
  3. /attribution  -> same attribution object as the log?
  4. negative control: identical request, one flipped tag byte -> what changes?

The negative control is the part that matters: if a corrupted tag is rejected
differently while ours returns the normal payload, the server really did validate
our mint.

  KEEP_TS=1  keep the captured created_at/sent_at instead of fresh ones
"""
import json, os, re, sys, time, base64, urllib.parse
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import adj8ios_pure as sg
from carve import carve_query, split_blob, block_ok

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURE = os.environ.get("CAPTURE", r"C:\Users\Apps\Downloads\wave_19may_install_newapp_ios8.chls")
KEEP_TS = os.environ.get("KEEP_TS", "") == "1"
CAMPAIGN = {
    "app_name": "waveapp",
    "device_name": "iPhone10,1",
    "os_name": "ios",
    "os_version": "16.7.15",
    "head_phase": [0x09],
    "adjust": {"app_token": "mrpexk5wqp6o",
               "sdk": "react-native5.6.0@ios5.6.2",
               "adj_signing_id": "1400000",
               "headers_id": "9",
               "algorithm": "adj8",
               "native_version": "3.67.0"},
}
UA = "WaveApp/3.8.0 CFNetwork/1410.1 Darwin/22.6.0"
TZ = "-0700"

raw = open(CAPTURE, "rb").read().decode("latin-1")
sigs = list(re.finditer(r'Signature signature="([A-Za-z0-9+/=]+)"', raw))
SDK = CAMPAIGN["adjust"]["sdk"]

# ---- carve the three verified requests, in stream order ---------------------
WANT = [("session", lambda p: "session_count" in p and "source" not in p and "initiated_by" not in p),
        ("click",   lambda p: p.get("source") and "initiated_by" not in p),
        ("attribution", lambda p: "initiated_by" in p)]

found = []
for i, m in enumerate(sigs):
    blob = base64.b64decode(m.group(1))
    if len(blob) != 176:
        continue
    pt, _, _ = split_blob(blob)
    pos = m.start()
    anchors = [x.start() for x in
               re.finditer(r'(?:app_version|bundle_id|app_token|idfv|idfa)=', raw[:pos])]
    hit = None
    for a in reversed(anchors[-4:]):
        params = dict(urllib.parse.parse_qsl(carve_query(raw, a), keep_blank_values=True))
        if 'app_token' not in params:
            continue
        for kind, pred in WANT:
            if pred(params) and block_ok(pt, params, kind, SDK):
                hit = (kind, params, pos)
                break
        if hit:
            break
    if hit and hit[0] not in [f[0] for f in found]:
        found.append(hit)
    if len(found) == 3:
        break

if not found:
    sys.exit("no verified requests found")

# ---- the logged responses, in stream order ----------------------------------
logged = [m.group(0) for m in
          re.finditer(r'\{"app_token":"[^"]+","adid":"[0-9a-f]{32}"[^\x00]{0,700}', raw)]

def fmt(dt=None):
    dt = dt or datetime.now(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ%s" % (dt.microsecond // 1000, TZ)

from curl_cffi import requests as cr
S = cr.Session(impersonate="safari17_0")

ENDPOINT = {"session": "/session", "click": "/sdk_click",
            "attribution": "/attribution", "info": "/sdk_info"}

def fire(kind, params, method="POST", corrupt=False):
    t = int(time.time()) + 1
    while time.time() < t:
        time.sleep(0.02)
    p = dict(params)
    if not KEEP_TS:
        p["created_at"] = p["sent_at"] = fmt()
    auth = sg.sign_request(p, kind, c=CAMPAIGN, second=t)
    if corrupt:                       # flip the last tag byte
        b = bytearray(base64.b64decode(re.search(r'signature="([^"]+)"', auth).group(1)))
        b[-1] ^= 0x01
        auth = re.sub(r'signature="[^"]+"',
                      'signature="%s"' % base64.b64encode(bytes(b)).decode(), auth)
    host = ("https://consent.adjust.com" if p.get("att_status") == "3"
            else "https://analytics.adjust.com")
    h = {"User-Agent": UA, "Client-Sdk": SDK, "Authorization": auth}
    path = ENDPOINT.get(kind, "/" + kind)
    if method == "GET":
        return S.get(host + path + "?" + urlencode(p), headers=h, timeout=30)
    h["Content-Type"] = "application/x-www-form-urlencoded"
    return S.post(host + path, data=p, headers=h, timeout=30)


def jloads_loose(t):
    """json.loads on the first complete JSON object in a carve-bleeding string."""
    i = t.find('{"app_token"')
    if i < 0:
        return None
    dec = json.JSONDecoder()
    try:
        obj, _end = dec.raw_decode(t[i:])
        return obj
    except ValueError:
        return None

print("KEEP_TS=%s | host rule: consent when att_status=3 else analytics\n" % bool(KEEP_TS))
results = []
for kind, params, pos in found:
    method = "GET" if kind == "attribution" else "POST"
    print("=" * 78)
    print("%-12s %d params | att_status=%s | %s"
          % (kind, len(params), params.get("att_status"),
             "GET" if method == "GET" else "POST"), flush=True)
    r = fire(kind, params, method)
    print("   ours  : %s | %s" % (r.status_code, r.text[:420]), flush=True)
    results.append({"kind": kind, "status": r.status_code, "body": r.text[:2000],
                    "params": params})
    time.sleep(3)

print("\n" + "=" * 78)
print("LOGGED responses (in stream order)")
for i, l in enumerate(logged):
    print("  [%d] %s" % (i, l[:420]))
print("\nOURS")
for r in results:
    print("  %-12s %s | %s" % (r["kind"], r["status"], r["body"][:420]))

# ---- attribution field-by-field + negative control --------------------------
attr_res = [r for r in results if r["kind"] == "attribution"]
if attr_res:
    ours = attr_res[0]["body"]
    logged_attr = [l for l in logged if '"attribution":' in l]
    print("\n=== attribution: logged vs ours ===")
    if logged_attr:
        L = jloads_loose(logged_attr[0])
        O = jloads_loose(ours)
        la, oa = (L or {}).get("attribution", {}), (O or {}).get("attribution", {})
        print("  adid logged=%s ours=%s %s"
              % ((L or {}).get("adid"), (O or {}).get("adid"),
                 "same" if (L or {}).get("adid") == (O or {}).get("adid") else "DIFF"))
        for k in sorted(set(la) | set(oa)):
            same = la.get(k) == oa.get(k)
            print("  %-24s logged=%-26s ours=%-26s %s"
                  % (k, str(la.get(k))[:26], str(oa.get(k))[:26],
                     "same" if same else "DIFF"))
        if la.get("tracker_token") == oa.get("tracker_token") and \
           la.get("tracker_name") == oa.get("tracker_name") and \
           la.get("engagement_time") == oa.get("engagement_time"):
            print("\n  MATCH: our signed replay reproduces the logged attribution object")
    print("\n=== negative control (one flipped tag byte) ===")
    kind, params, pos = [f for f in found if f[0] == "attribution"][0]
    r = fire("attribution", params, "GET", corrupt=True)
    print("   corrupt: %s | %s" % (r.status_code, r.text[:300]))

json.dump({"capture": os.path.basename(CAPTURE), "keep_ts": bool(KEEP_TS),
           "requests": [{"kind": k, "params": p} for k, p, _ in found],
           "logged_responses": logged, "our_responses": results},
          open(os.path.join(HERE, "replay_attr_result.json"), "w"), indent=1)
print("\nwrote replay_attr_result.json")
