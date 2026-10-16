# -*- coding: utf-8 -*-
"""probe_adshustle3.py -- the new offer 22353289 and the bare Adjust link.

Probes:
  1. the tracker offer link, bare / +sub3 / +idfa  -> what Adjust tracker,
     campaign and adgroup does it map to?
  2. the direct Adjust link the user supplied (idfa only, NO click_id)
     -> does it register, and what does it answer?
"""
import re
import uuid

import requests

OFFER = "http://click-adshustle.appanalytics.in/api/track/v1/click?aff_id=2&offer_id=22353289"
OLD_OFFER = ("http://click-adshustle.appanalytics.in/api/track/v1/click"
             "?aff_id=2&offer_id=22352108&sub1={dp2}&sub2=vecwx2&sub3={gaid}")
DIRECT = ("https://app.adjust.com/1t8ghv6f?campaign=GWM&adgroup=%7B43407%7D"
          "&cost_type=cpi&cost_amount=1&cost_currency=USD&idfa={idfa}")

BROWSER_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 "
              "Mobile/15E148 Safari/604.1")


def show(label, url):
    print("=" * 76)
    print(label)
    print("=" * 76)
    r = requests.get(url, headers={"User-Agent": BROWSER_UA},
                     allow_redirects=False, timeout=30)
    loc = r.headers.get("Location") or ""
    print("  HTTP %s" % r.status_code)
    print("  Location: %s" % (loc or "(none)"))
    if "app.adjust.com" in loc:
        for k, v in re.findall(r"[?&]([^=&]+)=([^&]*)", loc):
            print("     %-20s %s" % (k, v[:110]))
    print()
    return loc


if __name__ == "__main__":
    idfa = str(uuid.uuid4()).upper()
    print("idfa:", idfa, "\n")

    print("### 1. NEW offer 22353289 (bare) ###")
    show("bare", OFFER)
    print("### 2. NEW offer + sub3=<idfa> ###")
    show("+sub3", OFFER + "&sub1=2&sub2=vecwx2&sub3=" + idfa)
    print("### 3. NEW offer + idfa=  ###")
    show("+idfa", OFFER + "&sub1=2&sub2=vecwx2&idfa=" + idfa)
    print("### 4. OLD offer 22352108 for comparison ###")
    show("old", OLD_OFFER.replace("{dp2}", "2").replace("{gaid}", idfa))
    print("### 5. the DIRECT Adjust link (idfa only, no click_id) ###")
    show("direct", DIRECT.replace("{idfa}", idfa))