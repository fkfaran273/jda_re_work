# -*- coding: utf-8 -*-
"""probe_adshustle.py -- find the Adjust link behind the adshustle click URL.

The tracker only hands out the app.adjust.com link to a browser-looking
client (same wall as trckswrm).  Fire it with a real browser UA, walk the
302 chain, and print every hop so we can see which device params it
forwards (sub3=gaid is a publisher macro -- on iOS the device match is idfa=).

Variants tried:
    base        sub3=<gaid>                      (the given link)
    +idfa       sub3=<gaid> & idfa=<idfa>        (does it forward idfa?)
    +gaid       gaid=<gaid>                      (named param variant)
    +both       everything
"""
import re
import sys
import uuid

import requests

TRACKER = ("http://click-adshustle.appanalytics.in/api/track/v1/click"
           "?aff_id=2&offer_id=22352108&sub1={dp2}&sub2=vecwx2&sub3={gaid}")

BROWSER_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 "
              "Mobile/15E148 Safari/604.1")

IDFA = str(uuid.uuid4()).upper()
GAID = (uuid.uuid4().hex + uuid.uuid4().hex)[:32].upper()


def gaid():
    return (uuid.uuid4().hex + uuid.uuid4().hex)[:32].upper()


def hop(url, n=4):
    """Walk the redirect chain, printing every hop."""
    print("  " + url)
    for _ in range(n):
        r = requests.get(url, headers={"User-Agent": BROWSER_UA},
                         allow_redirects=False, timeout=30)
        loc = r.headers.get("Location") or r.headers.get("location")
        print("     -> %s  %s" % (r.status_code, (loc or r.text[:90])[:200]))
        if r.status_code not in (301, 302, 303, 307, 308) or not loc:
            return r, loc
        url = loc
    return r, None


def variant(label, extra):
    print("=" * 78)
    print(label)
    print("=" * 78)
    url = (TRACKER.replace("{dp2}", "2").replace("{gaid}", gaid()) + extra)
    r, loc = hop(url)
    print()
    if loc and "app.adjust.com" in loc:
        print("  >>> ADJUST LINK:")
        print("  " + loc)
        print()
        print("  params:")
        for k, v in re.findall(r"[?&]([^=&]+)=([^&]*)", loc):
            print("     %-22s %s" % (k, v))
    print()
    return loc


if __name__ == "__main__":
    print("idfa:", IDFA)
    print()
    variant("A. base (sub3=gaid only)", "")
    variant("B. + idfa", "&idfa=" + IDFA)
    variant("C. + gaid", "&gaid=" + gaid())
    variant("D. + both", "&idfa=" + IDFA + "&gaid=" + gaid())