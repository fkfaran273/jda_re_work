r"""join_chain_probe.py — WHAT in the click->session->sdk_click chain gates the
click->install JOIN (the Organic / tracker wy7261z result)?

Established (do not re-derive):
  * the adj9 signature envelope is NOT verified server-side
  * only Client-SDK / Content-Type / Host are enforced headers on /sdk_click
  * every well-formed attempt so far books Organic, tracker_token=wy7261z,
    engagement_time=0001-01-01T00:00:00Z

This harness walks the hypothesis space of the chain itself:

  E1 ORDER      session->click (baseline) / click->session / click only
  E2 REPEAT     /sdk_click sent 1 / 2 / 3 times
  E3 REFTAG     own verbatim / already-consumed reftag / fresh foreign reftag
  E4 TIMING     installed_at 30d / 24h / 1h / 5s ago, and 1h in the FUTURE
  E5 COUNTERS   click body session_count/subsession_count/session_length/
                time_spent  0 vs 1/1/0/0 (genuine) vs 7/3/1042/938
  E6 SOURCE     source=install_referrer vs other, referrer_api present/absent

Every cell:
  * a FRESH uuid4 GAID (never the connected device's), a fresh android_uuid
  * a REAL tracker click first (unless the cell explicitly substitutes a
    foreign/consumed reftag)
  * the install timeline is always in the past unless the cell says otherwise
  * 2-3 s between every outbound request

SAFETY: no adb, no frida, no proxy, no DNAT, no installs. The device is never
touched.  Usage:  python join_chain_probe.py [exp_id ...]

Results are appended to join_chain_probe.json after EVERY cell (crash-safe).
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_full_chain as fc              # transport, DEV/fmt
import offline_funnel_freshregion as F    # build_*/mint_signed/LINK/CTIT
import click_bind_chain as CBC            # expand()/tracker_click()

OUT = os.path.join(HERE, "join_chain_probe.json")
DEVICE_GAID = "f476b3d4-e0b1-4707-bc43-6153d17f7f8c"   # never use
SESSION_URL = "https://app.adjust.com/session"
CLICK_URL = "https://app.adjust.com/sdk_click"
ATTR_URL = "https://app.adjust.com/attribution"

RESULTS = []      # completed cells
USED_REFTAGS = []  # [(reftag, gps)] reftags already burned by a completed cell


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------
def fresh_gaid():
    g = str(uuid.uuid4())
    assert g != DEVICE_GAID, "refusing to use the device GAID"
    return g


def own_tracker_click(gps):
    """REAL click on the campaign with gps_adid stamped on -> own reftag."""
    link = CBC.expand(CBC.LINK, gps)
    code, ref, hops = CBC.tracker_click(link, gps)
    return code, ref


def foreign_tracker_click():
    """A real click bound to a THROWAWAY adid; returns its reftag only."""
    throw = fresh_gaid()
    code, ref, hops = CBC.tracker_click(CBC.expand(CBC.LINK, throw), throw)
    return code, ref, throw


def post_session(gps, auid, ins, over=None):
    sec = int(time.time()) - 2
    p = F.build_session(gps, auid, ins, sec)
    p.update(over or {})
    b, _ = F.mint_signed("session", p, sec)
    time.sleep(2.5)
    return fc.send(SESSION_URL, p, b)


def post_click(gps, auid, ref, ins, updated=None, strip=(), over=None):
    sec = int(time.time()) - 2
    p = F.build_sdk_click(gps, auid, ref, 0, 0, ins, sec)
    if updated is not None:
        p["updated_at"] = updated
    p.update(over or {})
    # a field dropped from the wire stays in the signed claims: the server does
    # not verify the envelope, so this isolates the BODY field.
    for k in strip:
        p.pop(k, None)
    b, _ = F.mint_signed("click", p, sec)
    time.sleep(2.5)
    return fc.send(CLICK_URL, p, b)


def poll_attr(gps, auid, n=2, gap=12):
    out = []
    for k in range(n):
        sec = int(time.time()) - 2
        p = F.build_attribution(gps, auid, sec)
        b, _ = F.mint_signed("attribution", p, sec)
        time.sleep(2.5)
        out.append(fc.send(ATTR_URL, p, b, method="GET"))
        if k < n - 1:
            time.sleep(gap)
    return out


def read_attr(polls):
    a = {}
    for s, r in polls:
        try:
            a = json.loads(r)["attribution"]
            break
        except Exception:
            continue
    if not a:
        return {"network": None, "tracker_token": None, "verdict": "PARSE_FAIL",
                "raw": polls[-1][1][:300] if polls else ""}
    adid = None
    for s, r in polls:
        try:
            adid = json.loads(r).get("adid")
            break
        except Exception:
            continue
    return {"network": a.get("network"),
            "tracker_token": a.get("tracker_token"),
            "tracker_name": a.get("tracker_name"),
            "engagement_time": a.get("engagement_time"),
            "is_reattributed": a.get("is_reattributed"),
            "installed_at": a.get("installed_at"),
            "first_session_time": a.get("first_session_time"),
            "adid": adid}


def short(s, n=180):
    return (s or "")[:n]


# ---------------------------------------------------------------------------
# one experiment cell
# ---------------------------------------------------------------------------
def run_cell(spec):
    gps = fresh_gaid()
    auid = fresh_gaid()
    ins_off = spec.get("ins_offset", -20)      # seconds from now (may be +)
    ins = fc.fmt(int(time.time()) + ins_off, 431).decode()
    upd = None
    if spec.get("upd_offset") is not None:
        upd = fc.fmt(int(time.time()) + spec["upd_offset"], 431).decode()
    elif ins_off > 0:                          # keep updated_at >= installed_at
        upd = ins

    rec = {"id": spec["id"], "exp": spec["exp"], "variation": spec["variation"],
           "gps": gps, "auid": auid, "installed_at_stamp": ins,
           "steps": []}

    # ---- the click -------------------------------------------------------
    mode = spec.get("reftag", "own")
    if mode == "own":
        code, ref = own_tracker_click(gps)
        rec["steps"].append(["tracker_click", code])
        if not ref or "adjust_reftag=" not in ref:
            rec["verdict"] = "NO_REFTAG"
            return rec
        burn = True
    elif mode == "consumed":
        # a reftag already used by an EARLIER, completed cell (bound to a
        # different, already-installed adid)
        code, ref = 0, None
        if USED_REFTAGS:
            ref, prev = USED_REFTAGS[0]
            rec["steps"].append(["reuse_consumed_reftag_from", prev])
        else:
            rec["verdict"] = "NO_CONSUMED_REFTAG_AVAILABLE"
            return rec
        burn = False
    elif mode == "foreign":
        code, ref, throw = foreign_tracker_click()
        rec["steps"].append(["foreign_tracker_click", code, throw])
        burn = False
    else:
        raise ValueError(mode)
    rec["reftag"] = ref.split("adjust_reftag=", 1)[1].split("&")[0]
    rec["referrer"] = ref

    # ---- session / click ordering ---------------------------------------
    order = spec.get("order", "session_click")
    n_click = spec.get("clicks", 1)
    cov = spec.get("click_over") or {}
    sov = spec.get("session_over") or {}
    strip = tuple(spec.get("strip") or ())

    if order in ("session_click", "session_only"):
        rec["steps"].append(["session", *post_session(gps, auid, ins, sov)])
    if order == "click_session":
        s, r = post_click(gps, auid, ref, ins, upd, strip, cov)
        rec["steps"].append(["click#1", s, short(r)])
        time.sleep(2.5)
        rec["steps"].append(["session", *post_session(gps, auid, ins, sov)])
        for k in range(2, n_click + 1):
            s, r = post_click(gps, auid, ref, ins, upd, strip, cov)
            rec["steps"].append(["click#%d" % k, s, short(r)])
    elif order == "click_only":
        for k in range(1, n_click + 1):
            s, r = post_click(gps, auid, ref, ins, upd, strip, cov)
            rec["steps"].append(["click#%d" % k, s, short(r)])
    else:  # session_click
        for k in range(1, n_click + 1):
            s, r = post_click(gps, auid, ref, ins, upd, strip, cov)
            rec["steps"].append(["click#%d" % k, s, short(r)])

    rec["polls"] = [[s, short(r, 1200)] for s, r in
                    poll_attr(gps, auid, n=spec.get("polls", 2))]
    rec["attribution"] = read_attr(rec["polls"])
    rec["verdict"] = "%s / %s / eng=%s / reattr=%s" % (
        rec["attribution"].get("tracker_token"),
        rec["attribution"].get("network"),
        rec["attribution"].get("engagement_time"),
        rec["attribution"].get("is_reattributed"))
    if burn:
        USED_REFTAGS.append((ref, gps))
    return rec


# ---------------------------------------------------------------------------
# the cell list
# ---------------------------------------------------------------------------
CELLS = [
    # ---- E1 ORDER --------------------------------------------------------
    {"id": "E1a", "exp": "E1", "variation": "session then click (baseline)",
     "order": "session_click", "polls": 3},
    {"id": "E1b", "exp": "E1", "variation": "click FIRST, then session",
     "order": "click_session"},
    {"id": "E1c", "exp": "E1", "variation": "click only, NO session at all",
     "order": "click_only", "polls": 3},
    # ---- E2 REPEAT -------------------------------------------------------
    {"id": "E2b", "exp": "E2", "variation": "/sdk_click sent TWICE (1 dup)",
     "clicks": 2, "polls": 3},
    {"id": "E2c", "exp": "E2", "variation": "/sdk_click sent THREE times",
     "clicks": 3, "polls": 3},
    # ---- E3 REFTAG -------------------------------------------------------
    #  E3a is E1a's baseline (own reftag, verbatim)
    {"id": "E3b", "exp": "E3", "variation": "ALREADY-CONSUMED reftag "
     "(from the E1a cell, different adid already installed)",
     "reftag": "consumed"},
    {"id": "E3c", "exp": "E3", "variation": "FRESH FOREIGN reftag (real click "
     "by a throwaway adid that never installs)",
     "reftag": "foreign"},
    # ---- E4 TIMING -------------------------------------------------------
    {"id": "E4a", "exp": "E4", "variation": "installed_at 30 days ago",
     "ins_offset": -30 * 86400},
    {"id": "E4b", "exp": "E4", "variation": "installed_at 24h ago",
     "ins_offset": -86400},
    {"id": "E4c", "exp": "E4", "variation": "installed_at 1h ago",
     "ins_offset": -3600},
    {"id": "E4d", "exp": "E4", "variation": "installed_at 5s ago (tightest)",
     "ins_offset": -5},
    {"id": "E4e", "exp": "E4", "variation": "installed_at 1h in the FUTURE",
     "ins_offset": 3600},
    {"id": "E4f", "exp": "E4", "variation": "updated_at 5 days AFTER "
     "installed_at", "ins_offset": -20, "upd_offset": 5 * 86400},
    # ---- E5 COUNTERS -----------------------------------------------------
    #  E5a is E1a's baseline (genuine 1/1/0/0)
    {"id": "E5b", "exp": "E5", "variation": "click counters ALL ZERO",
     "click_over": {"session_count": "0", "subsession_count": "0",
                    "session_length": "0", "time_spent": "0"}},
    {"id": "E5c", "exp": "E5", "variation": "click counters realistic "
     "7/3/1042/938 (session body left at genuine 1)",
     "click_over": {"session_count": "7", "subsession_count": "3",
                    "session_length": "1042", "time_spent": "938"}},
    {"id": "E5d", "exp": "E5", "variation": "click AND session counters both "
     "realistic 7/3/1042/938",
     "click_over": {"session_count": "7", "subsession_count": "3",
                    "session_length": "1042", "time_spent": "938"},
     "session_over": {"session_count": "7"}},
    # ---- E6 SOURCE -------------------------------------------------------
    #  E6a is E1a's baseline (source=install_referrer, referrer_api=google)
    {"id": "E6b", "exp": "E6", "variation": "source='organic' (signed too)",
     "click_over": {"source": "organic"}},
    {"id": "E6c", "exp": "E6", "variation": "source ABSENT from wire body "
     "(still in signature)", "strip": ("source",)},
    {"id": "E6d", "exp": "E6", "variation": "referrer_api ABSENT from wire "
     "body (still in signature)", "strip": ("referrer_api",)},
]


def main():
    want = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--send" not in sys.argv:
        print("dry run: add --send to go live")
        return 1
    for spec in CELLS:
        if want and spec["id"] not in want and spec["exp"] not in want:
            continue
        print("=== %s  %s ===" % (spec["id"], spec["variation"]), flush=True)
        t0 = time.time()
        try:
            r = run_cell(spec)
        except Exception as e:
            r = {"id": spec["id"], "exp": spec["exp"],
                 "variation": spec["variation"],
                 "verdict": "EXC %s: %s" % (type(e).__name__, e)}
        r["secs"] = round(time.time() - t0, 1)
        RESULTS.append(r)
        for s in r.get("steps", []):
            print("    %s" % (s if not isinstance(s, list)
                              else [s[0], s[1]] + list(s[2:3])), flush=True)
        print("    ATTR:", json.dumps(r.get("attribution", {})), flush=True)
        print("    VERDICT: %s   (%.0fs)" % (r.get("verdict"), r["secs"]),
              flush=True)
        json.dump({"device_gaid_never_used": True,
                   "fresh_gaid_per_cell": True,
                   "cells": RESULTS}, open(OUT, "w"), indent=1)
    print("\nsaved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
