"""attempt3_phase_a.py — record the tracker click NOW; save funnel state.

The 3-5 minute gap between click and first session is deliberate: it
gives a plausible click-to-install time (CTIT), which agency offers
filter on. Phase B (after the wait) sends session-first, then sdk_click.
"""
import datetime
import json
import random
import re
import time
import urllib.error
import urllib.request
import uuid

EC2 = "http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def iso(now, off=0.0, ms="000"):
    return (now + datetime.timedelta(seconds=off)).strftime(
        "%Y-%m-%dT%H:%M:%S." + ms + "Z+0200")


adid = str(uuid.uuid4())
auuid = str(uuid.uuid4())
click_id = "%032x" % random.getrandbits(128)
url = ("https://app.adjust.com/1sd1lk6a"
       "?gps_adid=" + adid +
       "&campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
       "&click_id=" + click_id +
       "&install_callback=" + EC2 + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
       "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
       "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
       "&event_callback_bfi71x=" + EC2 + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
       "click_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust"
       "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")
req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
opener = urllib.request.build_opener(NoRedirect)
now = datetime.datetime.now(datetime.timezone.utc)
try:
    r = opener.open(req, timeout=30)
    code, loc = r.status, r.headers.get("Location")
except urllib.error.HTTPError as e:
    code, loc = e.code, e.headers.get("Location")
print("click -> %d" % code)
print("loc   : %s" % (loc or "")[:150])
reftag = None
if loc:
    m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc)
    if m:
        reftag = m.group(1)
print("reftag:", reftag)
assert reftag, "no reftag minted"
state = {
    "gps_adid": adid, "android_uuid": auuid, "click_id": click_id,
    "reftag": reftag,
    "click_time": iso(now, 0, "100"),
    "click_time_server": iso(now, 1, "100"),
    "install_begin_time": iso(now, 95, "200"),
    "install_begin_time_server": iso(now, 96, "200"),
    "installed_at": iso(now, 175, "400"),
    "updated_at": iso(now, 175, "400"),
}
json.dump(state, open("attempt3_state.json", "w"), indent=1)
print("saved attempt3_state.json")
print("state:", json.dumps(state, indent=1))
