"""attempt4_phase_a.py — click the EXACT network link: idfa={sub3} carries
our (new) adid, click_id macro substituted, NO gps_adid param, no other
changes. Funnel (attempt4_phase_b) then mirrors attempt 3 exactly, so the
click-field placement is the only variable vs the non-organic real
non-rooted installs."""
import datetime
import json
import random
import re
import urllib.error
import urllib.request
import uuid

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
cb = "http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
URL = ("https://app.adjust.com/1sd1lk6a"
       "?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
       "&click_id=" + click_id +
       "&idfa=" + adid +
       "&install_callback=" + cb + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
       "click_id%3D" + click_id + "%26p_sub1%3Dadjust%26advertising_id%3D"
       "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
       "&event_callback_bfi71x=" + cb + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
       "click_id%3D" + click_id + "%26goal%3Dbfi71x%26p_sub1%3Dadjust"
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
json.dump(state, open("attempt4_state.json", "w"), indent=1)
print("saved attempt4_state.json")
