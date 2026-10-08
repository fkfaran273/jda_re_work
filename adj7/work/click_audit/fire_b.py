"""Test B: dedup probe -- fire the SAME click URL twice immediately (cookie jar
kept), 3 fresh rounds; also one 3rd fire after 65s. Compares reftags."""
import json, time, uuid, urllib.parse, email.utils
from curl_cffi import requests as cr

URL = "https://app.adjust.com/1yzhva5b"
UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
FULL_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7")
HDRS = {"User-Agent": UA, "Accept": FULL_ACCEPT,
        "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "identity",
        "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1"}

def fire(s, url):
    t0 = time.time()
    r = cr.get(url, headers=HDRS, timeout=30, allow_redirects=False,
               impersonate="chrome131_android")
    loc = r.headers.get("location", "")
    reftag = None
    if "referrer=" in loc:
        seg = urllib.parse.unquote(loc.split("referrer=",1)[1].split("&")[0])
        reftag = seg
    d = r.headers.get("date")
    return {"status": r.status_code, "reftag": reftag,
            "date_sec": int(email.utils.parsedate_to_datetime(d).timestamp()) if d else None,
            "set_cookie": r.headers.get("set-cookie","")[:120],
            "cookie_name": r.headers.get("set-cookie","").split("=")[0],
            "elapsed": round(time.time()-t0,3)}

results = {}
for rnd in range(1, 4):
    gaid = str(uuid.uuid4())
    url = URL + "?gps_adid=" + gaid
    s = cr.Session()
    hits = []
    for i in range(2):                       # immediate double-fire
        h = fire(s, url)
        h["when"] = round(time.time(), 3)
        hits.append(h)
        time.sleep(0.4)                      # well inside the 2s cookie window
    # third fire after ~65 s from the SAME session (cookie long expired)
    time.sleep(65)
    h3 = fire(s, url)
    h3["when"] = round(time.time(), 3)
    hits.append(h3)
    results["round%d" % rnd] = {"gaid": gaid, "hits": hits}
    tags = [h["reftag"] for h in hits]
    print("round%d reftags: %s  double-same=%s" % (rnd, [t[:13] for t in tags],
                                                   tags[0]==tags[1]))

json.dump(results, open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\click_audit\results_b.json","w"), indent=1)
print("saved results_b.json")
