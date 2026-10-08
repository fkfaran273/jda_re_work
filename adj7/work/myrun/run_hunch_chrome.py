"""run_hunch_chrome.py -- hunch funnel, CLICK transplanted to real Chrome TLS.

Hypothesis: the adjust click row is fraud-scored on TLS/client below HTTP.
Everything else stays ours: builders, signer, timing, API via http.client
(byte-exact headers). Only the click hop goes through curl_cffi BoringSSL
(impersonate=chrome124) DIRECT (no proxy -- Fiddler MITM would replace the
server-visible TLS and defeat the test).
"""
import json
import os
import re
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from curl_cffi.requests import Session
import run_hunch as H

LINK = H.LINK
MOBILE_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")

CHROME_HEADERS = {
    "User-Agent": MOBILE_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}


def chrome_click():
    """Fire LINK with Chrome TLS, manual redirect walk, return reftag."""
    clog = open(os.path.join(HERE, "click_chain_hunch_chrome.log"), "a")
    clog.write("=== %s TLS=chrome131_android-direct\n" % datetime.now().isoformat())
    s = Session(impersonate="chrome131_android")
    try:
        url = LINK
        for hop in range(8):
            prev = url
            r = s.get(url, headers=CHROME_HEADERS, allow_redirects=False,
                      timeout=30, verify=False)
            loc = r.headers.get("Location", "")
            clog.write("hop %s -> %s loc=%s setcookie=%s jar=%s\n"
                       % (url[:150], r.status_code, loc[:280],
                          r.headers.get("Set-Cookie", "")[:120],
                          str(dict((c.name, c.value[:8]) for c in s.cookies.jar))[:120]))
            print("click    hop -> %s jar_cookies=%d" % (r.status_code, len(s.cookies.jar)))
            if loc:
                # referrer header for the NEXT hop must be the previous URL,
                # as Chrome sends it
                CHROME_HEADERS["Referer"] = prev
                ref = H._reftag_in(loc)
                if ref and loc.startswith("http"):
                    # fire the adjust hop target too if http(s)
                    pass
                if ref:
                    # the adjust 302 Location IS the market URL; the click
                    # is logged by the GET we just did (url was the adjust
                    # link or its redirect). Return it.
                    clog.write("result ref=%s\n" % ref)
                    return ref
                url = loc if loc.startswith("http") else url
                if not loc.startswith("http"):
                    break
                continue
            break
        return None
    finally:
        clog.close()
        s.close()


def main():
    gaid = os.environ.get("FUNNEL_GAID") or str(uuid.uuid4())
    android_uuid = str(uuid.uuid4())
    started = time.time()
    print("HUNCH-CHROME  gaid=%s" % gaid)
    print("click: %s" % LINK)
    reftag = chrome_click()
    if not reftag:
        print("no reftag -- aborting")
        return 1
    print("click    reftag %s  [t=+%.0fs]" % (reftag, time.time() - started))
    click_second = int(time.time()) - 1
    wait = click_second + H.SESSION_AT - time.time()
    if wait > 0:
        print("installing... (CTIT %.0fs)" % wait)
        time.sleep(wait)
    sec = H.signing_second()
    sf = H.build_session(gaid, android_uuid, sec, click_second)
    st, b = H.call("POST", "/session", sf, H.sign(sf, "session", sec))
    p = json.loads(b)
    print("session -> %s adid=%s ask_in=%s" % (st, p.get("adid"), p.get("ask_in")))
    time.sleep(0.3)
    sec2 = H.signing_second()
    cf = H.build_click(gaid, android_uuid, sec2, reftag, click_second)
    st2, b2 = H.call("POST", "/sdk_click", cf, H.sign(cf, "click", sec2))
    print("sdk_click -> %s" % st2)
    verdict = {}
    for i in range(6):
        time.sleep(3.2 if i == 0 else 1.5)
        sec3 = H.signing_second()
        af = H.build_attr(gaid, android_uuid, sec3)
        _s, b3 = H.call("GET", "/attribution", af,
                        H.sign(af, "attribution", sec3))
        p3 = json.loads(b3)
        verdict = p3.get("attribution") or {}
        print("poll %-2d -> %-9s / %-9s ask_in=%s [t=+%.0fs]"
              % (i + 1, verdict.get("network"), verdict.get("tracker_token"),
                 p3.get("ask_in"), time.time() - started))
        if verdict.get("network") and verdict["network"] != "Organic":
            break
        if verdict.get("network") == "Organic" and not p3.get("ask_in") and i >= 2:
            break
    print("FINAL: %s" % json.dumps(verdict))
    open(os.path.join(HERE, "last_run_hunch_chrome.json"), "w").write(
        json.dumps({"gaid": gaid, "reftag": reftag,
                    "attribution": verdict}, indent=1))
    if verdict.get("network", "Organic") != "Organic":
        print("*** NON-ORGANIC *** %.0fs" % (time.time() - started))
    else:
        print("*** Organic *** %.0fs" % (time.time() - started))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
