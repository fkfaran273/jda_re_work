"""attempt6_phase_a.py — verbatim link, idfa=<adid> (as attempt 5), but
funnel fires phase_b after a REAL ~5 min gap so click/install_begin/
installed_at are all genuinely in the PAST at session time (attempt 5's
flaw: session 6 s after a click claiming install_begin at +95 s)."""
import datetime
import json
import random
import re
import time
import urllib.error
import urllib.request
import uuid

UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")
CB = ("http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def iso(now, off=0.0, ms="000"):
    return (now + datetime.timedelta(seconds=off)).strftime(
        "%Y-%m-%dT%H:%M:%S." + ms + "Z+0200")


adid = str(uuid.uuid4())
auuid = str(uuid.uuid4())
URL = ("https://app.adjust.com/1sd1lk6a"
       "?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
       "&click_id={click_id}&idfa=" + adid +
       "&install_callback=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
       "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
       "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
       "&event_callback_bfi71x=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
       "click_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust"
       "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")

req = urllib.request.Request(URL, method="GET", headers={"User-Agent": UA})
opener = urllib.request.build_opener(NoRedirect)
now = datetime.datetime.now(datetime.timezone.utc)
try:
    r = opener.open(req, timeout=30)
    code, loc = r.status, r.headers.get("Location")
except urllib.error.HTTPError as e:
    code, loc = e.code, e.headers.get("Location")
print("click -> %d" % code)
print("loc   : %s" % (loc or "")[:160])
m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc or "")
reftag = m.group(1) if m else None
print("reftag:", reftag)
assert reftag, "no reftag"
state = {
    "gps_adid": adid, "android_uuid": auuid, "reftag": reftag,
    "click_epoch": time.time(),
    "click_time": iso(now, 0, "100"),
    "click_time_server": iso(now, 1, "100"),
    "install_begin_time": iso(now, 120, "200"),
    "install_begin_time_server": iso(now, 121, "200"),
    "installed_at": iso(now, 200, "400"),
    "updated_at": iso(now, 200, "400"),
}
json.dump(state, open("attempt6_state.json", "w"), indent=1)
print("saved attempt6_state.json — run phase_b after >=3 min")
