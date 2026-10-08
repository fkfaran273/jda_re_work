"""Test A: fire the direct adjust link with different header sets / gps_adid variants.
No project files modified; results saved to work/click_audit/results_a.json"""
import json, time, uuid, urllib.parse, email.utils

URL = "https://app.adjust.com/1yzhva5b"
ANDROID_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
DESKTOP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
FULL_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7")

def hdrs_min(ua): return {"User-Agent": ua}

def hdrs_funnel(ua):
    return {"User-Agent": ua,
            "Accept": FULL_ACCEPT,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"}

def hdrs_realnav(ua):
    h = hdrs_funnel(ua)
    h.update({"Referer": "https://mobpine.com/offer/23483498",
              "Sec-Fetch-Site": "cross-site",
              "Sec-CH-UA": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
              "Sec-CH-UA-Mobile": "?1",
              "Sec-CH-UA-Platform": '"Android"',
              "Accept-Encoding": "gzip, deflate, br, zstd"})
    return h

VARIANTS = [
    # (label, client, ua, header-builder, extra query)
    ("A1_plain_requests_minhdr_android",      "requests",  ANDROID_UA, hdrs_min,    ""),
    ("A2_cffi_funnelhdr_android_nogps",       "cffi",      ANDROID_UA, hdrs_funnel, ""),
    ("A3_cffi_funnelhdr_android_gps_valid",   "cffi",      ANDROID_UA, hdrs_funnel, "&gps_adid={g1}"),
    ("A4_cffi_funnelhdr_android_gps_malformed","cffi",     ANDROID_UA, hdrs_funnel, "&gps_adid=not-a-uuid"),
    ("A5_cffi_funnelhdr_android_gps_macro",   "cffi",      ANDROID_UA, hdrs_funnel, "&gps_adid=%7Bgps_adid%7D"),
    ("A6_cffi_funnelhdr_android_adj_gps_valid","cffi",     ANDROID_UA, hdrs_funnel, "&adj_gps_adid={g2}"),
    ("A7_cffi_realnavhdr_android_referer",    "cffi",      ANDROID_UA, hdrs_realnav,"&gps_adid={g3}"),
    ("A8_plain_requests_minhdr_android_gps",  "requests",  ANDROID_UA, hdrs_min,    "&gps_adid={g4}"),
    ("A9_cffi_funnelhdr_desktop",             "cffi",      DESKTOP_UA, hdrs_funnel, ""),
]

def run_request(client, url, headers):
    """return list of hops: (status, headers-dict, body-snippet)"""
    hops = []
    if client == "requests":
        import requests
        s = requests.Session()
        s.headers.update(headers)
        u = url
        for i in range(6):
            r = s.get(u, allow_redirects=False, timeout=30)
            hops.append((r.status_code, dict(r.headers), (r.text or "")[:300]))
            loc = r.headers.get("Location") or r.headers.get("location")
            if not loc or not (loc.startswith("http://") or loc.startswith("https://")):
                break
            u = loc
    else:
        from curl_cffi import requests as cr
        u = url
        for i in range(6):
            r = cr.get(u, headers=headers, timeout=30, allow_redirects=False,
                       impersonate="chrome131_android")
            hops.append((r.status_code, {k.lower(): v for k, v in r.headers.items()}, (r.text or "")[:300]))
            loc = hops[-1][1].get("location")
            if not loc or not (loc.startswith("http://") or loc.startswith("https://")):
                break
            u = loc
    return hops

def reftag_of(hops):
    # from last hop Location (market:// or intent://) or body
    last_loc = None
    for st, h, body in hops:
        if isinstance(h, dict):
            last_loc = h.get("location") or h.get("Location") or last_loc
    blob = (last_loc or "") + " || " + " || ".join(b for _,_,b in hops)
    if "referrer=" in blob:
        seg = blob.split("referrer=",1)[1]
        seg = seg.split("&",1)[0] if "&" in seg.split(";",1)[0] else seg.split(";",1)[0]
        seg = seg.split(";",1)[0]
        return urllib.parse.unquote(seg)
    return None

results = {}
subs = {"g1": str(uuid.uuid4()), "g2": str(uuid.uuid4()),
        "g3": str(uuid.uuid4()), "g4": str(uuid.uuid4())}
for label, client, ua, hb, extra in VARIANTS:
    url = URL + ("?" + extra.format(**subs).lstrip("&") if extra else "")
    t0 = time.time()
    try:
        hops = run_request(client, url, hb(ua))
    except Exception as e:
        results[label] = {"error": repr(e), "url": url}
        continue
    rec = {"url": url, "elapsed": round(time.time()-t0,2), "hops": []}
    for st, h, body in hops:
        hh = {k: v for k, v in h.items() if k.lower() in (
            "location","set-cookie","date","content-type","server","cache-control",
            "x-adjust","via","alt-svc")}
        rec["hops"].append({"status": st, "headers": hh, "body": body})
    rec["reftag"] = reftag_of(hops)
    results[label] = rec
    print(label, "->", [h[0] for h in hops], "reftag:", (rec["reftag"] or "")[:80])
    time.sleep(2)

json.dump(results, open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\click_audit\results_a.json","w"), indent=1)
print("saved results_a.json")
