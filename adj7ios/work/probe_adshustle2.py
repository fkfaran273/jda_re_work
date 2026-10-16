# -*- coding: utf-8 -*-
"""probe_adshustle2.py -- full Adjust link behind the adshustle tracker,
and which param actually joins on iOS.

The tracker 302s us app.adjust.com/1t8ghv6f with sub3 copied into gps_adid.
AGENTS.md law: on iOS the device match is idfa=; a publisher macro only
counts when the tracker forwards it INTO the link.  So we must find out
which of these joins:
    L1  gps_adid=<idfa>            (tracker forwarded our idfa as sub3)
    L2  idfa=<idfa>  + gps_adid=<idfa>
    L3  idfa=<idfa>  only
"""
import re
import uuid

import requests

TRACKER = ("http://click-adshustle.appanalytics.in/api/track/v1/click"
           "?aff_id=2&offer_id=22352108&sub1=2&sub2=vecwx2&sub3={gaid}")
BROWSER_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 "
              "Mobile/15E148 Safari/604.1")


def tracker_302(idfa):
    """Fire the tracker with sub3=<idfa>, return the raw Adjust Location."""
    url = TRACKER.replace("{gaid}", idfa)
    r = requests.get(url, headers={"User-Agent": BROWSER_UA},
                     allow_redirects=False, timeout=30)
    loc = r.headers.get("Location") or ""
    if not loc:
        raise SystemExit("no 302 (status %s)" % r.status_code)
    return loc


def show(label, url):
    print("=" * 78)
    print(label)
    print("=" * 78)
    print(url)
    print("  params:")
    for k, v in re.findall(r"[?&]([^=&]+)=([^&]*)", url):
        print("     %-22s %s" % (k, v))
    print()


if __name__ == "__main__":
    idfa = str(uuid.uuid4()).upper()
    print("idfa:", idfa)
    print()

    raw = tracker_302(idfa)
    show("RAW tracker 302 (sub3 = our idfa)", raw)

    # L1: as the tracker built it -- gps_adid carries our idfa
    show("L1  gps_adid=<idfa> only  (tracker verbatim)", raw)

    # L2: add the explicit iOS device-match param alongside
    l2 = raw.replace("&install_callback", "&idfa=" + idfa + "&install_callback")
    if "&idfa=" not in l2:
        l2 = raw + "&idfa=" + idfa
    show("L2  gps_adid=<idfa> + idfa=<idfa>", l2)

    # L3: drop gps_adid, keep only idfa
    l3 = re.sub(r"[?&]gps_adid=[^&]*", "", raw)
    if "?" not in l3:
        l3 += "?" + l3.split("?", 1)[1]
    l3 = l3.replace("&idfa=", "")
    l3 = l3 + ("&" if "?" in l3 else "?") + "idfa=" + idfa
    show("L3  idfa=<idfa> only (gps_adid removed)", l3)