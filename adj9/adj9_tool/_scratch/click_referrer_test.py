"""MODE B, automated: fire a REAL click, capture the REAL referrer, install with
the GAID the click was tied to, then poll the verdict.

This is the honest end-to-end. MODE A fired the click but then hardcoded the
referrer to 'utm_medium=organic', so Adjust could never match the install to the
click. Here we take the actual referrer from the tracker's 302 Location header
(the same string a real device receives via the market:// install referrer) and
report THAT, tied to the same gps_adid the click was registered under.

If this goes NON-ORGANIC, the signature was never the blocker -- the missing
piece was the click-matched referrer, and our forged adj9 is sufficient.
"""
import sys
import os
import time
import uuid
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote_plus
from urllib.error import HTTPError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_api as A
import adj9_signer as S

LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH"
        "&adgroup=vkm_0926_36&creative=cline_1p8t3"
        "&click_id={click_id}&gps_adid={click_id}")


def fire_and_capture():
    """Return (gps_adid, referrer, t_click) for a freshly fired real click."""
    cid = str(uuid.uuid4())                       # fresh GAID per run
    url = LINK.replace("{click_id}", cid)
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent",
                   "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S1RHS32.34-83-10)")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    op = urllib.request.build_opener(NoRedirect)
    t_click = time.time()
    try:
        r = op.open(req, timeout=45)
        code, hdrs = r.getcode(), dict(r.getheaders())
    except HTTPError as e:
        code, hdrs = e.code, dict(e.headers)
    loc = hdrs.get("location", "")
    print("  click HTTP %s" % code)
    if not loc:
        print("  NO REDIRECT -- cannot extract referrer")
        return None
    qs = urlparse(loc).query
    ref = parse_qs(qs).get("referrer", [""])[0]
    # parse_qs already URL-decodes; keep the literal referrer string.
    print("  referrer: %s" % ref)
    return cid, ref, t_click


def main():
    print("=" * 62)
    print(" adj9 MODE B-auto  (real click -> real referrer -> install)")
    print("=" * 62)
    api = A.Api(transport="pc")

    print("\nSTEP 1/3  fire a real click and capture its referrer")
    got = fire_and_capture()
    if not got:
        print("click capture failed"); return 1
    gps, referrer, t_click = got

    auid = str(uuid.uuid4())
    print("  gps_adid    : %s" % gps)
    print("  android_uuid: %s" % auid)

    # small CTIT, like a real fast install
    CTIT = 4.0
    ins = api.fmt(int(t_click) + int(CTIT), 431).decode()
    tb = t_click + 2.0

    print("\nSTEP 2/3  install (session + sdk_click with the REAL referrer)")
    time.sleep(max(0, (t_click + CTIT) - time.time()))
    code, body = api.session(gps, auid, installed_at=ins)
    print("  /session    -> %s %s" % (code, body[:100]))
    code, body = api.sdk_click(gps, auid, referrer, t_click, tb, ins)
    print("  /sdk_click  -> %s %s" % (code, body[:100]))

    print("\nSTEP 3/3  polling attribution")
    verdict = None
    for i in range(5):
        time.sleep(1 if i == 0 else 12)
        code, body = api.attribution(gps, auid)
        v = A.read_verdict(body)
        if v:
            verdict = v
            print("  poll %d/5  %s token=%s network=%s eng=%s => %s"
                  % (i + 1, code, v["token"], v["network"],
                     v["engagement_time"], v["verdict"]))
            if not v["organic"]:
                break
        else:
            print("  poll %d/5  %s (no verdict yet)" % (i + 1, code))

    print("\n" + "=" * 62)
    print(" VERDICT: %s" % (verdict["verdict"] if verdict else "NO VERDICT"))
    print("=" * 62)
    import json
    with open(os.path.join(HERE, "last_run.json"), "w") as f:
        json.dump({"gps_adid": gps, "referrer": referrer,
                   "verdict": verdict}, f, indent=1)
    print("saved last_run.json")


if __name__ == "__main__":
    main()
