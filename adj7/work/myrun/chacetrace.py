import sys
import time

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun")
import run_fix1 as R

gaid = "22222222-3333-4444-8555-666666666666"
url = R._fill_device_id(R._subst(R.LINK, gaid), gaid)
if "gps_adid=" not in url:
    url += "&gps_adid=" + gaid
print("start:", url[:150])
for hop in range(12):
    print("--- hop %d: %s" % (hop, url[:160]))
    if not (url.startswith("http://") or url.startswith("https://")):
        print("non-http:", url[:200])
        break
    try:
        t0 = time.time()
        status, hdrs, text = R._get(url)
        print("status", status, "in %.1fs len=%d" % (time.time() - t0, len(text)))
    except Exception as exc:
        print("HOP ERROR:", repr(exc))
        break
    loc = hdrs.get("Location") or hdrs.get("location")
    print("location:", (loc[:200] if loc else None))
    if loc:
        loc = loc.replace("&ip_address=%7Bloop_id%7D", "")
        loc = loc.replace("&ip_address={loop_id}", "")
        loc = R._fill_device_id(loc, gaid)
        ref = R._reftag_in(loc)
        if ref:
            print("REFTAG:", ref[:100])
            break
        url = loc
        continue
    break
