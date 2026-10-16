# -*- coding: utf-8 -*-
"""replay_lululemon.py -- the ATTRIBUTION REPLAY RULE on the lululemon
capture (consent.adjust.com, adj7 / native 3.62.0 / headers_id 8).

Logged verdict (13 May 2026, sid hit-2): a BOOKED non-organic --
  tracker 20ql0xil / network admatic / campaign admatic_2 / adgroup
  admatic_2 / creative 2126_n8349d, engagement 2026-05-13T04:54:59Z,
  installed_at = first_session_time = 2026-05-13T05:15:48Z,
  adid 9d755291bd3d4180be3e7c0c9fe4c160.

The rule: re-send the attribution through OUR signature making; the
signature layer must behave exactly like the genuine one (G control),
and if the booking row still holds, ours must return it verbatim.
A row whose booking has aged out answers Organic to ANYONE -- including
the genuine signature (established on nirio + adj7-Android replays);
there G == O == Organic is the signature-layer pass, not a mint defect.

Probes
  G    genuine verbatim: the carved raw query + the capture's own sig
  O    ours: same map, fresh second + nonce
  ARM  our signed /session -> wait ask_in -> our signed /attribution
"""
import json
import re
import sys
import time

import requests

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7ios")
import adj7ios_pure as sg                                   # noqa: E402
from verify_chls import carve_chunk, find_map, parse_params  # noqa: E402

CHLS = r"C:\Users\Apps\Downloads\lululemon_newapp_13may_ios11.chls"
UA = "lululemonTurkiye/82 CFNetwork/3860.400.51 Darwin/25.3.0"
SDK = "react-native5.5.0@ios5.5.0"
HOST = "https://consent.adjust.com"
HID, NV = "8", "3.62.0"

LOGGED = {"adid": "9d755291bd3d4180be3e7c0c9fe4c160",
          "tracker_token": "20ql0xil", "network": "admatic",
          "campaign": "admatic_2", "engagement_time": "2026-05-13T04:54:59Z",
          "installed_at": "2026-05-13T05:15:48Z"}


def load():
    raw = open(CHLS, "rb").read().decode("latin-1")
    sigs = [m for m in
            re.finditer(r'Signature signature="([0-9A-Fa-f]{608})"', raw)]
    out = {}
    for m in sigs:
        back = raw[max(0, m.start() - 2500):m.start()]
        eps = [e for e in ("sdk_click", "session", "attribution", "event")
               if ("/" + e) in back]
        ep = eps[-1] if eps else "?"
        mp = find_map(raw, m.start())
        out[ep] = {"sig": m.group(1), "raw_query": mp[1],
                   "params": parse_params(mp[1])}
    return out


def hdrs(auth=None):
    h = {"User-Agent": UA, "Client-Sdk": SDK, "Accept": "*/*",
         "Accept-Language": "tr-TR,tr;q=0.9"}
    if auth:
        h["Authorization"] = auth
    return h


def auth_of(sig):
    return ('Signature signature="%s",adj_signing_id="1300000",'
            'algorithm="adj7",headers_id="%s",native_version="%s"'
            % (sig, HID, NV))


def show(label, r):
    try:
        j = r.json()
    except ValueError:
        j = {}
    a = j.get("attribution") or {}
    print("[%s] HTTP %s  adid=%s ask_in=%s"
          % (label, r.status_code, j.get("adid"), j.get("ask_in")))
    if a:
        print("      tracker=%s network=%s campaign=%s engage=%s"
              " installed=%s"
              % (a.get("tracker_token"), a.get("network"),
                 a.get("campaign"), a.get("engagement_time"),
                 a.get("installed_at")))
    else:
        print("      body:", r.text[:160])
    return j, a


def main():
    reqs = load()
    atr, ses = reqs["attribution"], reqs["session"]
    f_atr = atr["params"]
    # the carved chunk swallows the URL path prefix -- strip it so G is the
    # exact wire query
    raw_q = re.sub(r"^[a-z_]+\?", "", atr["raw_query"])
    url_q = HOST + "/attribution?" + raw_q

    print("logged (13 May): adid=%s tracker=%s network=%s campaign=%s\n"
          % (LOGGED["adid"], LOGGED["tracker_token"], LOGGED["network"],
             LOGGED["campaign"]))

    out = {}

    # G -- genuine verbatim
    r = requests.get(url_q, headers=hdrs(auth_of(atr["sig"])), timeout=30)
    gj, ga = show("G genuine verbatim", r)
    out["G"] = {"http": r.status_code, "json": gj}
    time.sleep(3)

    # O -- ours, fresh sig, same map
    auth_o, _ = sg.sign_request(f_atr, "attribution", client_sdk=SDK)
    r = requests.get(HOST + "/attribution", params=f_atr,
                     headers=hdrs(auth_o), timeout=30)
    oj, oa = show("O ours fresh sig", r)
    out["O"] = {"http": r.status_code, "json": oj}
    time.sleep(3)

    # ARM -- our session -> ask_in -> our attribution
    auth_s, _ = sg.sign_request(ses["params"], "session", client_sdk=SDK)
    h = hdrs(auth_s)
    h["Content-Type"] = "application/x-www-form-urlencoded"
    r1 = requests.post(HOST + "/session", data=ses["params"], headers=h,
                       timeout=30)
    sj, _ = show("ARM session ours", r1)
    out["ARM_session"] = {"http": r1.status_code, "json": sj}
    ask = None
    try:
        ask = sj.get("ask_in")
    except Exception:
        pass
    if r1.status_code == 200 and ask:
        time.sleep(ask / 1000.0 + 2)
        auth_a, _ = sg.sign_request(f_atr, "attribution", client_sdk=SDK)
        r2 = requests.get(HOST + "/attribution", params=f_atr,
                          headers=hdrs(auth_a), timeout=30)
        aj, aa = show("ARM attribution ours", r2)
        out["ARM_attribution"] = {"http": r2.status_code, "json": aj}
        armed = (aa or {})
    else:
        armed = {}

    # ---- verdict -------------------------------------------------------
    def state(a, http, adid):
        if http != 200:
            return "http %s" % http
        if not a:
            return "no attribution object (adid %s)" % adid
        if a.get("tracker_token") == LOGGED["tracker_token"] \
                and a.get("network") == LOGGED["network"]:
            return "BOOKED VERDICT REPRODUCED"
        if a.get("network") == "Organic":
            return "Organic (row re-evaluated)"
        return "state: %s/%s" % (a.get("tracker_token"), a.get("network"))

    print("\n================= REPLAY RULE =================")
    rows = {"G genuine": (ga, out["G"]["http"], gj.get("adid")),
            "O ours": (oa, out["O"]["http"], oj.get("adid")),
            "ARM ours": (armed, out.get("ARM_attribution", {}).get("http"),
                         (out.get("ARM_attribution", {}).get("json")
                          or {}).get("adid"))}
    for k, (a, http, adid) in rows.items():
        if http is None:
            print("  %-12s not run" % k)
            continue
        print("  %-12s %s" % (k, state(a, http, adid)))
    sig_layer = (rows["G genuine"][0].get("tracker_token"),
                 rows["G genuine"][0].get("network")) == \
        (rows["O ours"][0].get("tracker_token"),
         rows["O ours"][0].get("network")) and \
        out["G"]["http"] == out["O"]["http"]
    booked = any("BOOKED" in state(a, h, d)
                 for a, h, d in rows.values() if h)
    print("\n  signature layer (ours == genuine): %s"
          % ("PASS" if sig_layer else "DIFFER -- investigate"))
    print("  logged booked verdict today      : %s"
          % ("REPRODUCED with our signature" if booked else
             "row answers differently (aged booking -- see G control)"))
    with open(r"C:\Users\Apps\Downloads\com.penti.app\adj7ios"
              r"\replay_lululemon_result.json", "w") as f:
        json.dump(out, f, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
