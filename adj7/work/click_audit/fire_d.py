"""Test D: (1) plain campaign=/adgroup= enrichment on 1yzhva5b;
(2) mobpine destination rotation over 6 fires."""
import json, time, uuid, urllib.parse, email.utils
from curl_cffi import requests as cr

UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
FULL_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7")
H = {"User-Agent": UA, "Accept": FULL_ACCEPT, "Accept-Language": "en-US,en;q=0.9",
     "Accept-Encoding": "identity", "Upgrade-Insecure-Requests": "1",
     "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
     "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1"}

def fire(url):
    r = cr.get(url, headers=H, timeout=30, allow_redirects=False,
               impersonate="chrome131_android")
    return r.status_code, r.headers.get("location",""), r.headers.get("date")

out = {}

# D1: device-shaped params on the direct hunch link
g = str(uuid.uuid4())
u = ("https://app.adjust.com/1yzhva5b?campaign=SOHYPE_ADH&adgroup=%7Baffiliate_id%7D"
     "&gps_adid=" + g)
st, loc, d = fire(u)
out["D1_device_shaped_params"] = {"status": st, "location": loc, "date": d}
print("D1", st, loc[:220])

time.sleep(2)
# D2: also with click_id + install_callback + ip_address macro (full mobpine shape)
g2 = str(uuid.uuid4())
u2 = ("https://app.adjust.com/1yzhva5b?campaign=SOHYPE_ADH&adgroup=%7Baffiliate_id%7D"
      "&click_id=TESTCID123&ip_address=%7Bloop_id%7D&gps_adid=" + g2 +
      "&install_callback=http%3A%2F%2Fmp-pb.appanalytics.in%2Ftest")
st, loc, d = fire(u2)
out["D2_full_mobpine_shape"] = {"status": st, "location": loc, "date": d}
print("D2", st, loc[:220])

# D3: mobpine rotation, 6 fires 3s apart, NO gps (see what affiliate fills)
rots = []
for i in range(6):
    g3 = str(uuid.uuid4())
    u3 = "http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23483498&sub3=" + g3
    st, loc, d = fire(u3)
    rec = {"status": st, "loc1": loc[:400], "date": d}
    if loc.startswith("http"):
        st2, loc2, d2 = fire(loc)          # follow to the next hop
        rec["status2"] = st2; rec["loc2"] = loc2[:300]; rec["date2"] = d2
    rots.append(rec)
    print("D3 fire%d:" % i, st, loc[:150])
    print("      ->", rec.get("loc2","")[:180])
    time.sleep(3)
out["D3_mobpine_rotation"] = rots

json.dump(out, open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\click_audit\results_d.json","w"), indent=1)
print("saved results_d.json")
