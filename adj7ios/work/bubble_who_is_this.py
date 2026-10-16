# -*- coding: utf-8 -*-
"""bubble_who_is_this.py -- which app does each tracker actually point at?

Every BubbleBus click came back Organic with the same Organic token, across
four click shapes.  Before blaming the funnel, check the pairing: fire each
tracker's link all the way through and read the landing page -- it names the
store app.  The berain tracker (20yvzdd5, a KNOWN booking) is the control:
if its page names id1298014792 and the adshustle one names something else,
the tracker/app pairing is the wall, not our signature or join.

Also reports the app token the tracker belongs to, if the page exposes it.
"""
import re
import sys
import uuid

import requests

BROWSER_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 "
              "Mobile/15E148 Safari/604.1")

TARGETS = {
    "CONTROL berain 20yvzdd5 (books)":
        "https://app.adjust.com/20yvzdd5?campaign=TMV+May_Derby"
        "&adgroup=NP_SH_Q&os_name=ios&idfa={idfa}&gps_adid={idfa}"
        "&click_id=z{cid}",
    "adshustle 1t8ghv6f GWM":
        "https://app.adjust.com/1t8ghv6f?campaign=GWM&adgroup=%7B43407%7D"
        "&cost_type=cpi&cost_amount=1&cost_currency=USD&idfa={idfa}"
        "&gps_adid={idfa}&click_id=z{cid}",
    "adshustle 1t8ghv6f AH":
        "https://app.adjust.com/1t8ghv6f?campaign=AH&adgroup=43407"
        "&cost_type=cpi&cost_amount=1&cost_currency=USD&idfa={idfa}"
        "&gps_adid={idfa}&click_id=z{cid}",
}


def walk(label, tmpl):
    idfa = str(uuid.uuid4()).upper()
    cid = uuid.uuid4().hex[:12]
    url = tmpl.replace("{idfa}", idfa).replace("{cid}", cid)
    print("=" * 76)
    print(label)
    print("=" * 76)
    print("  idfa %s" % idfa)
    s = requests.Session()
    s.headers["User-Agent"] = BROWSER_UA
    for hop in range(8):
        r = s.get(url, allow_redirects=False, timeout=30)
        loc = r.headers.get("Location") or ""
        print("  hop %d: %s  len=%d" % (hop, r.status_code, len(r.content or b"")))
        if loc:
            print("     -> %s" % loc[:150])
            url = loc
            continue
        body = (r.text or "")
        title = re.search(r"<title>(.*?)</title>", body, re.S | re.I)
        print("     title: %s" % (title.group(1).strip() if title else "(none)"))
        store = sorted(set(re.findall(r"id(\d{6,})", body)))
        print("     App Store ids in page: %s" % (store or "(none)"))
        urls = sorted(set(re.findall(r"https?://[^\"'\s<>]{6,120}", body)))
        for u in urls[:14]:
            print("       %s" % u[:120])
        if not urls:
            print("     body head: %s" % body[:300].replace("\n", " "))
        break
    print()


if __name__ == "__main__":
    for label, tmpl in TARGETS.items():
        walk(label, tmpl)