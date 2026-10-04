r"""join_fingerprint_test.py — attack the ONE remaining gate: click->install join.

What is already proven (do not re-litigate)
------------------------------------------
  * The adj9 signature is NOT the install-booking gate.  unsigned_control.py
    fired /session with a valid sig, a 1-bit-flipped sig, NO sig, and a garbage
    sig; all four booked a real adid.  Booking is signature-agnostic.
  * Descriptor #8 (and every other descriptor) is therefore off the critical
    path.  The signature does not have to be perfect to book.

What is still open
------------------
The corrected funnel (offline_funnel_freshregion.py) booked installs but every
attribution came back Organic (wy7261z, engagement_time 0001-01-01): the click
never JOINED the install.  Two candidate causes, both tested here:

  Arm A  FINGERPRINT-ONLY
      click the tracker bound to fresh GAID G  ->  /session on the SAME G
      -> poll /attribution.   NO /sdk_click at all.
      Theory: the click is fingerprinted server-side (IP + stamped gps_adid);
      when the install reports the same GAID from the same IP, Adjust joins them
      with no Play install_referrer in the loop.  This is the true OFFLINE goal.

  Arm B  FINGERPRINT + CORRECTED /sdk_click
      click tracker (GAID G2) -> /session(G2) -> /sdk_click(G2, reftag,
      source=install_referrer, click_time) -> poll /attribution.
      The earlier funnel shipped a STALE updated_at (2026-09-08, 18 days before
      the click) because it only overwrote installed_at.  A server sanity-checking
      timestamp order (updated_at vs installed_at vs click_time) could have been
      dropping this.  build_sdk_click now sets updated_at == installed_at.

Both arms score on the ATTRIBUTION the server actually stores (attribution.network
!= "Organic"), NOT on HTTP 400/200.  The 400 + ask_in:7200000 signal is a 2-hour
poll backoff for an already-attributed device and is explicitly NOT a validity or
recognition signal — it is treated as "already attributed, back off", recorded
separately, and never counted as a join.

Safety / gating
---------------
  * dry-run by default; live send needs --send --confirm SEND-JOIN-FINGERPRINT
  * fresh GAID (uuid4) per arm, NEVER the connected device's GAID
  * device is NOT touched: no adb, no frida, no proxy, no DNAT
  * every mint uses a FRESH VALID region (F.py), never ZERO0/HRAND

Usage
-----
  python join_fingerprint_test.py                                     # dry-run
  python join_fingerprint_test.py --send --confirm SEND-JOIN-FINGERPRINT
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_full_chain as fc
import offline_funnel_freshregion as F          # fresh-region mint + builders
import click_bind_chain as CBC                  # real tracker click primitive

OUT = os.path.join(HERE, "join_fingerprint_test_result.json")

# attribution poll backoff (s) — enough to let the join propagate
POLL_BACKOFF = [0, 8, 20, 35]


def _click(gps):
    """Stamp gps on the real tracker link, follow to the adjust reftag."""
    link = CBC.expand(F.LINK, gps)
    t_click = int(time.time())
    code, ref, hops = CBC.tracker_click(link, gps)
    return {"http": code, "referrer": ref, "t_click": t_click, "hops": hops}


def _require_reftag(click, rec):
    ref = click.get("referrer") or ""
    if "adjust_reftag=" not in ref:
        rec["verdict"] = "NO_REFTAG (click did not resolve to adjust_reftag)"
        return False
    return True


def _poll(gps, auid, rec, label):
    """Poll /attribution; record every poll; return the winning verdict."""
    polls = []
    for k, wait in enumerate(POLL_BACKOFF):
        if wait:
            time.sleep(wait)
        sec_a = int(time.time()) - 2
        pa = F.build_attribution(gps, auid, sec_a)
        ba, ia = F.mint_signed("attribution", pa, sec_a)
        s, r = fc.send("https://app.adjust.com/attribution", pa, ba,
                       method="GET")
        poll = {"http": s, "resp": r[:2000], "backoff": wait}
        att = None
        if s == 200:
            try:
                att = json.loads(r).get("attribution")
            except Exception:
                att = None
        poll["attribution"] = att
        poll["backoff_signal"] = ("ask_in" in (r or ""))
        polls.append(poll)
        print("    poll%d (+%2ds) http=%s %s" % (
            k, wait, s, (("net=%s tok=%s" % (att.get("network"),
                                             att.get("tracker_token")))
                         if att else "(no attribution obj)")), flush=True)
        if att and att.get("network") and att["network"] != "Organic":
            rec["steps"][label + "_polls"] = polls
            return "NON_ORGANIC %s / %s / eng=%s" % (
                att.get("tracker_token"), att.get("network"),
                att.get("engagement_time"))
    rec["steps"][label + "_polls"] = polls
    # settled verdict from the last poll that carried an attribution object
    last_att = None
    for p in polls:
        if p.get("attribution"):
            last_att = p["attribution"]
    if last_att is None:
        if any(p.get("backoff_signal") for p in polls):
            return "ALREADY_ATTRIBUTED_BACKOFF (400+ask_in; device already attributed, not a join)"
        return "NO_ATTRIBUTION_OBJECT"
    return "ORGANIC %s / net=%s / eng=%s" % (
        last_att.get("tracker_token"), last_att.get("network"),
        last_att.get("engagement_time"))


def arm_fingerprint(send_live, rec):
    """Arm A: click + /session, NO /sdk_click. True offline fingerprint route."""
    gps = str(uuid.uuid4())        # fresh GAID, never the device's
    auid = str(uuid.uuid4())
    rec.update({"arm": "A/FINGERPRINT-ONLY", "gps": gps, "auid": auid,
                "steps": {}})
    click = _click(gps)
    rec["click"] = click
    print("    click http=%s reftag=%s" % (
        click["http"], (click["referrer"] or "").split("&")[0]), flush=True)
    if not _require_reftag(click, rec):
        return rec
    if not send_live:
        rec["verdict"] = "DRY_RUN"
        return rec

    t_click = click["t_click"]
    tb = t_click + F.CTIT
    ins = fc.fmt(tb + F.INS_LAG, 431).decode()

    # /session only — the install is reported, but with NO install_referrer
    sec_s = int(time.time()) - 2
    ps = F.build_session(gps, auid, ins, sec_s)
    bs, isig = F.mint_signed("session", ps, sec_s)
    rec["steps"]["session"] = {"info": isig}
    s, r = fc.send("https://app.adjust.com/session", ps, bs)
    rec["steps"]["session"]["http"] = s
    rec["steps"]["session"]["resp"] = r[:800]
    print("    /session http=%s" % s, flush=True)

    wait = (tb + F.INS_LAG + 3) - int(time.time())
    if wait > 0:
        time.sleep(wait)
    rec["verdict"] = _poll(gps, auid, rec, "A")
    return rec


def arm_fingerprint_click(send_live, rec):
    """Arm B: click + /session + CORRECTED /sdk_click (updated_at == installed_at)."""
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    rec.update({"arm": "B/FINGERPRINT+CLICK", "gps": gps, "auid": auid,
                "steps": {}})
    click = _click(gps)
    rec["click"] = click
    print("    click http=%s reftag=%s" % (
        click["http"], (click["referrer"] or "").split("&")[0]), flush=True)
    if not _require_reftag(click, rec):
        return rec
    if not send_live:
        rec["verdict"] = "DRY_RUN"
        return rec

    t_click = click["t_click"]
    ref = click["referrer"]
    tb = t_click + F.CTIT
    ins = fc.fmt(tb + F.INS_LAG, 431).decode()

    sec_s = int(time.time()) - 2
    ps = F.build_session(gps, auid, ins, sec_s)
    bs, isig = F.mint_signed("session", ps, sec_s)
    rec["steps"]["session"] = {"info": isig}
    s, r = fc.send("https://app.adjust.com/session", ps, bs)
    rec["steps"]["session"]["http"] = s
    rec["steps"]["session"]["resp"] = r[:800]
    print("    /session http=%s" % s, flush=True)

    # /sdk_click with the FIXED updated_at (== installed_at)
    sec_c = int(time.time()) - 2
    pc = F.build_sdk_click(gps, auid, ref, t_click, tb, ins, sec_c)
    bc, ic = F.mint_signed("click", pc, sec_c)
    rec["steps"]["sdk_click"] = {"info": ic,
                                 "updated_at": pc.get("updated_at"),
                                 "installed_at": pc.get("installed_at")}
    s, r = fc.send("https://app.adjust.com/sdk_click", pc, bc)
    rec["steps"]["sdk_click"]["http"] = s
    rec["steps"]["sdk_click"]["resp"] = r[:800]
    print("    /sdk_click http=%s (updated_at=%s)" % (s, pc.get("updated_at")),
          flush=True)

    wait = (tb + F.INS_LAG + 3) - int(time.time())
    if wait > 0:
        time.sleep(wait)
    rec["verdict"] = _poll(gps, auid, rec, "B")
    return rec


def self_check():
    """Network-free structural checks on the two arms' payloads."""
    out = {}
    gps, auid = str(uuid.uuid4()), str(uuid.uuid4())
    second = int(time.time()) - 2
    ins = fc.fmt(second - 170, 431).decode()

    ps = F.build_session(gps, auid, ins, second)
    out["session_updated_at_eq_installed"] = (
        ps.get("updated_at") == ps.get("installed_at"))
    bs, _ = F.mint_signed("session", ps, second, V=(second ^ 999) & 0xFFFFFFFF)
    out["session_len_192"] = (len(bs) == 192)

    pc = F.build_sdk_click(gps, auid, "x=1&adjust_reftag=abc", second,
                          second - 20, ins, second)
    out["click_updated_at_eq_installed"] = (
        pc.get("updated_at") == pc.get("installed_at"))
    out["click_updated_at_fresh"] = (second - 1) - (
        int(time.mktime(time.strptime(pc["updated_at"][:19],
              "%Y-%m-%dT%H:%M:%S")))) < 86400 if pc.get("updated_at") else False
    out["click_source_install_referrer"] = (
        pc.get("source") == "install_referrer")
    bc, _ = F.mint_signed("click", pc, second, V=(second ^ 999) & 0xFFFFFFFF)
    out["click_len_192"] = (len(bc) == 192)

    pa = F.build_attribution(gps, auid, second)
    ba, _ = F.mint_signed("attribution", pa, second,
                          V=(second ^ 999) & 0xFFFFFFFF)
    out["attr_len_192"] = (len(ba) == 192)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--confirm", default="")
    ap.add_argument("--arm", default="AB", help="subset of arms, e.g. A, B, AB")
    args = ap.parse_args()

    send_live = bool(args.send and args.confirm == "SEND-JOIN-FINGERPRINT")
    if args.send and not send_live:
        print("!! --send without exact --confirm; forcing dry-run.")

    print("=== SELF-CHECKS (network-free) ===")
    sc = self_check()
    for k, v in sc.items():
        print("  %-30s %s" % (k, v))
    must = ["session_updated_at_eq_installed", "session_len_192",
            "click_updated_at_eq_installed", "click_source_install_referrer",
            "click_len_192", "attr_len_192"]
    bad = [k for k in must if not sc.get(k)]
    if bad:
        print("!! SELF-CHECK FAILED:", bad)
        return 2
    print("  -> GREEN\n")

    arms = []
    if "A" in args.arm:
        arms.append(("A", arm_fingerprint))
    if "B" in args.arm:
        arms.append(("B", arm_fingerprint_click))

    print("=== PLAN ===")
    print("  mode:", "SEND" if send_live else "DRY-RUN")
    for tag, _ in arms:
        print("  arm", tag, "->",
              "click+/session, NO sdk_click" if tag == "A"
              else "click+/session+/sdk_click (fixed updated_at)")
    print("  fresh GAID per arm; device untouched\n")

    if not send_live:
        for tag, fn in arms:
            print("=== DRY arm %s ===" % tag)
            fn(False, {"steps": {}})
        print("\nUse --send --confirm SEND-JOIN-FINGERPRINT to go live.")
        return 0

    results = []
    for tag, fn in arms:
        print("=== LIVE arm %s ===" % tag, flush=True)
        rec = fn(True, {"steps": {}})
        print("  VERDICT:", rec["verdict"], flush=True)
        results.append(rec)

    json.dump(results, open(OUT, "w"), indent=1)
    print("\n=== SUMMARY ===")
    for r in results:
        print("  [%s] gps=%s -> %s" % (r["arm"], r["gps"][:8], r["verdict"]))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
