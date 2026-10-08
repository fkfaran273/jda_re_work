"""Test C: full mobpine chain (as the funnel fires it) + UA-less fire +
param-enrichment probe. Dumps every hop's Location."""
import json, time, uuid, urllib.parse, email.utils
from curl_cffi import requests as cr
import requests as rq

UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
FULL_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7")
FUNNEL_HDRS = {"User-Agent": UA, "Accept": FULL_ACCEPT,
               "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "identity",
               "Connection": "close", "Upgrade-Insecure-Requests": "1",
               "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
               "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1"}

def trace(client, url, headers, maxhops=12):
    hops = []
    u = url
    for i in range(maxhops):
        if not (u.startswith("http://") or u.startswith("https://")):
            hops.append({"status": None, "url": u[:500], "note": "non-http scheme (market/intent)"})
            break
        try:
            if client == "cffi":
                r = cr.get(u, headers=headers, timeout=30, allow_redirects=False,
                           impersonate="chrome131_android")
                hh = {k.lower(): v for k, v in r.headers.items()}
            else:
                r = rq.get(u, headers=headers, timeout=30, allow_redirects=False)
                hh = {k.lower(): v for k, v in r.headers.items()}
        except Exception as e:
            hops.append({"status": "ERR", "url": u[:300], "err": repr(e)})
            break
        loc = hh.get("location")
        hops.append({"status": r.status_code, "url": u[:300],
                     "location": (loc or "")[:500],
                     "date": hh.get("date"),
                     "set_cookie_names": [c.split("=")[0] for c in hh.get("set-cookie","").split(", ") if c][:3]})
        if not loc: break
        u = loc
    return hops

out = {}
gaid = str(uuid.uuid4())

# C1: mobpine chain exactly as funnel does (gps appended via _fill_device_id equivalent)
mob = ("http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23483498"
       "&sub3=" + gaid + "&gps_adid=" + gaid)
out["C1_mobpine_chain_gps"] = trace("cffi", mob, FUNNEL_HDRS)
time.sleep(2)

# C2: mobpine chain with NO gps anywhere
mob2 = "http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23483498&sub3=" + gaid
out["C2_mobpine_chain_nogps"] = trace("cffi", mob2, FUNNEL_HDRS)
time.sleep(2)

# C3: python-requests default UA (no UA override) straight at adjust
out["C3_adjust_default_ua"] = trace("rq", "https://app.adjust.com/1yzhva5b", {})
time.sleep(2)

# C4: client-side param enrichment on the direct link
out["C4_adjust_params_enrich"] = trace(
    "cffi", "https://app.adjust.com/1yzhva5b?adj_campaign=TESTCAMP99&adj_adgroup=GRP7&gps_adid=" + str(uuid.uuid4()),
    FUNNEL_HDRS)

for k, hops in out.items():
    print("="*100); print(k)
    for h in hops:
        st = h.get("status"); loc = h.get("location","")
        print("  [%s] %s" % (st, h.get("url","")[:120]))
        if loc: print("        -> %s" % loc[:220])
        if h.get("date"): print("        date: %s" % h["date"])
        if h.get("err"): print("        ERR %s" % h["err"])

json.dump(out, open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\click_audit\results_c.json","w"), indent=1)
# decode final referrers
for k, hops in out.items():
    for h in hops:
        loc = (h.get("location") or "") + (h.get("url") if h.get("note") else "")
        if "referrer=" in loc:
            print(k, "REFERRER:", urllib.parse.unquote(loc.split("referrer=",1)[1].split("&")[0])[:200])
            break
