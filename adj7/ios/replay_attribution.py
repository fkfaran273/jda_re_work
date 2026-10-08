# -*- coding: utf-8 -*-
"""replay_attribution.py — THE iOS VERIFICATION TOOL (adj8 replay rules).

Replays the BOOKED nirio iOS capture (consent.adjust.com, sid 39 attribution:
booked Kwanko_Optivads _DTS / tracker 24s38ts0, 08 Sep 2026) through OUR
signature maker (adj7_ios_pure).

modes:
  (default)      same-to-same: mint at the capture's second/nonce -> must be
                 BYTE-EXACT vs the captured signature; then live GET the
                 attribution with the capture's own params and compare the
                 verdict with the captured non-organic response.
  --fresh        mint at the CURRENT second, fresh nonce, created_at/sent_at
                 stamped now -> the un-throttled ask (the capture's stale
                 timestamps get Adjust's ask_in 3600000 throttle).
  --post eps     POST replay on eps in {third_party_sharing, session,
                 sdk_click} with the VALID / NONE / BROKEN signature triad —
                 probes whether the endpoint enforces the signature at all.

live findings (07 Oct 2026, one month after the capture):
  - our blobs are ACCEPTED everywhere (never a signature rejection);
  - the capture's non-organic verdict cannot re-assert: the booked click
    aged out of the attribution window (fresh ask -> Organic);
  - consent.adjust.com currently does NOT hard-reject broken signatures
    (attribution GET, third_party_sharing and session all answer the same
    with valid/none/broken) — so the decisive signature proof is the
    offline byte-exact mint (selftest 6/6), with the live replay proving
    transport acceptance end-to-end.

  python replay_attribution.py              # same-to-same replay
  python replay_attribution.py --fresh      # un-throttled ask, now
  python replay_attribution.py --post session
  FUNNEL_PROXY=http://user:pass@host:port   supported
"""
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

from adj7_ios_pure import sign_request  # noqa: E402

SID_ATTR = "39"
SID_TPS = "32"
SID_SESSION = "38"
SID_CLICK = "33"
UA = "Nirio/494 CFNetwork/1410.1 Darwin/22.6.0"
CLIENT_SDK = "react-native5.4.4@ios5.4.6"
HOST = "https://consent.adjust.com"
TZ = timezone(timedelta(hours=5, minutes=30))   # the capture's +0530 frame


def load_vector(sid):
    with open(os.path.join(HERE, "frozen_vectors.json"), encoding="utf-8") as f:
        vectors = json.load(f)
    v = [x for x in vectors if x["sid"] == sid][0]
    with open(os.path.join(HERE, "nirio_08Sep",
                           "nirioiosauto_08Sep_ios_CT_adjust.json"),
              encoding="utf-8") as f:
        recs = json.load(f)
    r = [x for x in recs if x["sid"] == sid][0]
    return v, r


def stamp_now(ts=None):
    """The capture's stamp shape: local +0530 digits + 'Z+0530'."""
    ts = time.time() if ts is None else ts
    dt = datetime.fromtimestamp(int(ts), TZ)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % int(ts % 1 * 1000) \
        + "Z+0530"


def _proxies():
    if os.environ.get("FUNNEL_PROXY"):
        p = os.environ["FUNNEL_PROXY"]
        return {"http": p, "https": p}
    return None


def send_get(path, params, auth):
    import requests
    url = HOST + path + "?" + urllib.parse.urlencode(
        params, quote_via=urllib.parse.quote)
    headers = {"User-Agent": UA, "Client-SDK": CLIENT_SDK, "Accept": "*/*",
               "Accept-Language": "en-US,en;q=0.9"}
    if auth:
        headers["Authorization"] = auth
    r = requests.get(url, headers=headers, timeout=30, proxies=_proxies())
    return r.status_code, r.text


def send_post(path, params, auth):
    import requests
    url = HOST + path
    headers = {"User-Agent": UA, "Client-SDK": CLIENT_SDK, "Accept": "*/*",
               "Content-Type": "application/x-www-form-urlencoded"}
    if auth:
        headers["Authorization"] = auth
    body = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    r = requests.post(url, data=body.encode(), headers=headers, timeout=30,
                      proxies=_proxies())
    return r.status_code, r.text


def mint(v, params, fresh):
    second = int(time.time()) if fresh else v["second"]
    nonce12 = os.urandom(12) if fresh else bytes.fromhex(v["nonce12"])
    return sign_request(params, v["kind"], second=second, nonce12=nonce12,
                        client_sdk=v["client_sdk"])


def replay_attr(fresh):
    v, cap = load_vector(SID_ATTR)
    cap_resp = json.loads(cap["response"])
    cap_attr = cap_resp.get("attribution") or {}
    print("=" * 74)
    print("iOS adj7 REPLAY  sid %s  (%s)" % (SID_ATTR, "FRESH" if fresh
                                             else "same-to-same"))
    print("captured verdict: network=%r tracker=%r adid=%s"
          % (cap_attr.get("network"), cap_attr.get("tracker_token"),
             cap_resp.get("adid", "")[:16] + ".."))
    print("=" * 74)

    params = dict(v["params"])
    if fresh:
        params["created_at"] = stamp_now()
        params["sent_at"] = stamp_now(time.time() + 0.047)
    auth, blob = mint(v, params, fresh)
    if fresh:
        print("mint  fresh blob %d B (fresh second + nonce + timestamps)"
              % len(blob))
    else:
        same = blob.hex().upper() == v["sig"]
        print("mint  %d B  vs captured 608-hex: %s"
              % (len(blob), "BYTE-EXACT" if same else "MISMATCH"))
        if not same:
            print("OFFLINE MISMATCH -- aborting live replay")
            return 1

    print("live  GET consent.adjust.com/attribution ...")
    status, body = send_get("/attribution", params, auth)
    print("      -> HTTP %d  %s" % (status, body[:160]))
    try:
        resp = json.loads(body)
        attr = resp.get("attribution") or {}
    except ValueError:
        print("VERDICT: non-JSON answer (throttle/reject)")
        return 1
    if not attr and resp.get("ask_in"):
        print("verdict: THROTTLED — ask_in %s ms (the capture's created_at is"
              " a month stale; run --fresh to stamp the ask now).  The adid"
              " %s... still resolves — request ACCEPTED"
              % (resp.get("ask_in"), resp.get("adid", "")[:16]))
        return 1
    network = attr.get("network")
    ok_live = (status == 200 and bool(attr)
               and network not in (None, "", "Organic"))
    same_verdict = (attr.get("tracker_token") == cap_attr.get("tracker_token")
                    and network == cap_attr.get("network"))
    print()
    if ok_live and same_verdict:
        print("*** NON-ORGANIC RETURNED, SAME AS LOGS — SIGNATURE VALID ***")
    elif ok_live:
        print("*** NON-ORGANIC RETURNED (verdict drifted from capture) —")
        print("    signature ACCEPTED; the capture is from 08 Sep")
    elif network == "Organic":
        print("verdict Organic — signature ACCEPTED (200 + full attribution")
        print("    flow on the same adid); the booked click aged out of the")
        print("    attribution window, so the logged verdict cannot re-assert")
    return 0


def post_probe(ep):
    sid = {"third_party_sharing": SID_TPS, "session": SID_SESSION,
           "sdk_click": SID_CLICK}[ep]
    v, cap = load_vector(sid)
    print("=" * 74)
    print("POST enforcement probe  /%s  (vector sid %s, kind %s)"
          % (ep, sid, v["kind"]))
    print("captured response: HTTP %s  %r" % (cap["status"],
                                              cap["response"][:70]))
    print("=" * 74)
    params = dict(v["params"])
    params["created_at"] = stamp_now()
    params["sent_at"] = stamp_now(time.time() + 0.047)
    auth, blob = mint(v, params, fresh=True)
    broken = auth[:24] + ("0" if auth[24] != "0" else "1") + auth[25:]
    for label, a in (("valid  ", auth), ("none   ", None),
                     ("broken ", broken)):
        status, body = send_post("/" + ep, params, a)
        print("%s -> HTTP %d  %r" % (label, status, body[:110]))
    print()
    print("note: identical answers for valid/none/broken mean the endpoint")
    print("      does not enforce the adj7 signature (device resolution by")
    print("      params); differing answers mean it does.")
    return 0


def main():
    argv = sys.argv[1:]
    if "--post" in argv:
        ep = argv[argv.index("--post") + 1] if (
            argv.index("--post") + 1 < len(argv)) else "session"
        if ep not in ("third_party_sharing", "session", "sdk_click"):
            print("unknown endpoint %r" % ep)
            return 2
        return post_probe(ep)
    return replay_attr("--fresh" in argv)


if __name__ == "__main__":
    raise SystemExit(main())
