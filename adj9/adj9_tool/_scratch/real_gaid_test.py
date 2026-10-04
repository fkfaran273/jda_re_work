"""Fire a real click tied to the DEVICE'S REAL advertising ID, then install with
the PYTHON signature using that same real GAID + the genuine adjust_reftag.

Hypothesis: every prior test used a random UUID GAID, which the server can never
attribute (not a real ad ID). A click tied to the device's actual advertising ID
(f476b3d4-..., the one the app's own captures use), installed via our forged
signature, should attribute if the signature is sufficient.
"""
import sys, os, time, uuid, urllib.request
from urllib.parse import urlparse, parse_qs
from urllib.error import HTTPError

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import adj9_api as A

DEVICE_GAID = "f476b3d4-e0b1-4707-bc43-6153d17f7f8c"   # the moto g42's real ad id
LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
        "&creative=cline_1p8t3&click_id={g}&gps_adid={g}")
CTIT = 4.0


def fire_click(gps):
    url = LINK.replace("{g}", gps)
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42)")
    class NR(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    t = time.time()
    try:
        r = urllib.request.build_opener(NR).open(req, timeout=45)
        loc = dict(r.getheaders()).get("location", "")
    except HTTPError as e:
        loc = dict(e.headers).get("location", "")
    ref = parse_qs(urlparse(loc).query).get("referrer", [""])[0]
    return ref, t


def main():
    api = A.Api(transport="pc")
    gps = DEVICE_GAID
    auid = str(uuid.uuid4())
    ref, t_click = fire_click(gps)
    print("=" * 62)
    print(" REAL-GAID click + PYTHON signature")
    print("=" * 62)
    print("  gps_adid :", gps, "(device's real advertising id)")
    print("  referrer :", ref[:110])
    sec = int(t_click) + int(CTIT)
    ins = api.fmt(sec, 431).decode()
    tb = t_click + 2.0
    time.sleep(max(0, (t_click + CTIT) - time.time()))
    code, body = api.session(gps, auid, installed_at=ins)
    print("  /session   ->", code, body[:80])
    code, body = api.sdk_click(gps, auid, ref, t_click, tb, ins)
    print("  /sdk_click ->", code, body[:80])
    verdict = None
    for i in range(5):
        time.sleep(1 if i == 0 else 12)
        code, body = api.attribution(gps, auid)
        v = A.read_verdict(body)
        if v:
            verdict = v
            print("  poll %d/5 %s token=%s network=%s eng=%s => %s"
                  % (i + 1, code, v["token"], v["network"],
                     v["engagement_time"], v["verdict"]), flush=True)
            if not v["organic"]:
                break
        else:
            print("  poll %d/5 %s (no verdict) %s" % (i + 1, code, body[:80]), flush=True)
    print("\n VERDICT:", verdict["verdict"] if verdict else "NO VERDICT", flush=True)


if __name__ == "__main__":
    main()
