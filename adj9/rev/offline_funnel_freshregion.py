r"""offline_funnel_freshregion.py — corrected OFFLINE click->install->attribution.

Why this file exists
--------------------
The earlier offline run (click_bind_chain.py, 2026-09-15) executed the real
funnel — tracker click (HTTP 302, genuine adjust_reftag) -> signed /session ->
signed /sdk_click -> /attribution poll — on a fresh GAID and got
``wy7261z / Organic`` on BOTH attempts.  That result looked like "offline
attribution is impossible", but it was an artifact: adj9_full_chain.mint_call
builds every blob with

    ZERO0 = True   -> descriptor #0 (d0, 144 B) = all zeros
    HRAND = True   -> descriptor #4 (d4,  32 B) = random bytes

i.e. the per-call region descriptors were STOMPED.  The signature could never be
valid, so the server booked every install Organic.  The run proved nothing about
whether a *valid* offline signature can earn a click join.

The F.py region model (rev/F.py, this session) makes #0/#2/#4 a pure function of
the fill seed  S = V ^ (pid<<16)  and reproduces the captured d0/d2/d4 10/10.
So the corrected test is exactly the same funnel, but every signature minted
with a FRESH, VALID region.

What this harness does (per attempt, always a FRESH GAID + fresh android_uuid):
  0. fresh gps_adid (GAID) and android_uuid — never the connected device's
  1. GET the tracker link with gps_adid stamped on  -> 302 + adjust_reftag
  2. mint+send /session   (valid fresh-region signature)
  3. mint+send /sdk_click (valid fresh-region signature, carries the reftag,
                           source=install_referrer, click/install timestamps)
  4. mint+send /attribution poll  -> read the stored attribution

Cells
-----
  V : the corrected cell   — fresh valid region on every request
  F : NEGATIVE control     — identical funnel, but the /session body has ONE
                             bit flipped (signature invalid).  If V and F score
                             identically the server is NOT checking the
                             signature and the whole test is uninformative.

Scoring is on the ATTRIBUTION the server actually stores, not on HTTP 400/200:
  NON_ORGANIC  = attribution.network != "Organic"  (a click joined)
  ORGANIC      = attribution.network == "Organic"  (no click joined)
  G0/CONTROL   = a verbatim, known-good record replayed verbatim (sanity only)

Safety / gating
---------------
  * dry-run by default: mints + self-checks + prints the exact requests, sends
    NOTHING.  Live send requires BOTH --send and --confirm SEND-OFFLINE-FRESHREGION
  * self-checks before any send: region laws, 192-B shape, header law,
    remint-is-byte-identical, reftag present, claims present
  * fresh GAID per attempt (uuid4), never the connected device's GAID
  * the device is NOT touched: no adb, no frida, no proxy, no DNAT

Usage
-----
  python offline_funnel_freshregion.py                     # dry-run, no traffic
  python offline_funnel_freshregion.py --attempts 2        # dry-run, 2 cells
  python offline_funnel_freshregion.py --send --confirm SEND-OFFLINE-FRESHREGION
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import struct
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_full_chain as fc          # byte-exact transport + click primitive
import mint_pipeline as MP             # fresh-region mint (claims -> descriptors)
import F                                # the region law (d0/d2/d4 from seed)

# ---- identity: the proven winner profile (moto g42 / api31 / os12 / +0530) ----
fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"

# The genuine tracker link (VKM Digital Yeni campaign) from click_bind_chain.py.
# gps_adid is stamped on at click time to bind the click to our fresh GAID.
LINK = fc.__dict__.get("LINK", None) or __import__("click_bind_chain").LINK
CLICK_UA = fc.__dict__.get("CLICK_UA", None) or __import__("click_bind_chain").CLICK_UA

S1P, S2P = fc.S1P, fc.S2P        # proven session / sdk_click param templates
APP_TOKEN = fc.APP_TOKEN

# click -> install_begin gap (s) and install_begin -> installed_at (s).
# The genuine winner used ~210 s and +7.431 s; we keep a sane, plausible gap.
CTIT = 20
INS_LAG = 7

OUT = os.path.join(HERE, "offline_funnel_freshregion_result.json")
PLAN = os.path.join(HERE, "offline_funnel_freshregion_plan.json")


# ---------------------------------------------------------------------------
# Fresh-region signing: the corrected core.
# ---------------------------------------------------------------------------
def fresh_region(second, head=None, V=None):
    """A FRESH, VALID (d0, d2, d4) for `second` via the F.py law.

    If `V` is None, take a fresh self-consistent fill instant (real clock µs,
    capped at the created_at ms) — the correct behaviour for a live signature.
    Pass an explicit `V` to get a byte-deterministic region (self-checks).

    DEFAULT HEAD CORRECTED 2026-09-28: this used to fall back to
    `F.HEAD_FIRST`, which is NOT what the device emits.  The 6-blob transport
    capture shows the three real request signings all use the 2-selector phase
    (0x2b, 0x48) = mint_pipeline.DEVICE_SELECTORS, and re-minting a genuine
    blob with it is byte-exact 192/192 (see blob_diff.md, _vf7.py).
    """
    if V is None:
        V = MP.make_V_consistent(second, 928)
    pid = MP.DEFAULT_PID
    d0w, d2w, d4w = F.region(V, pid, 0, head=head or MP.DEVICE_SELECTORS)
    d0b = b"".join(w.to_bytes(4, "big") for w in d0w)
    d2b = struct.pack(">I", d2w)
    d4b = b"".join(w.to_bytes(4, "big") for w in d4w)
    return d0b, d2b, d4b, {"V": V, "pid": pid}


def mint_signed(kind, params, second, head=None, flip_bit=False, V=None):
    """Mint a 192-B adj9 blob for `params` (wire form) with a FRESH VALID region.

    Returns (blob_192B, info).  Claims are derived from the wire params so the
    signed desc10 equals the wire byte-for-byte (the proven requirement).  The
    region (#0/#2/#4) is derived fresh from the seed via F.py — this is the
    correction over the old ZERO0/HRAND run.  Pass an explicit `V` for a
    byte-deterministic mint (self-checks); live mints leave V fresh.
    """
    claims = MP.claims_from_wire(params, kind)
    d0b, d2b, d4b, reg = fresh_region(second, head=head, V=V)
    descs, meta = MP.build_descriptors(claims, kind, d0b, d2b, d4b)
    blob, vm = MP.finex_mint(descs, second, max_steps=20_000_000)
    assert len(blob) == 192, "envelope must be 192 B"
    assert blob[:16] == MP.make_header(second), "header law broken"
    if flip_bit:
        # flip one bit of the FIRST body dword (byte 16, bit 0) -> invalid sig
        b = bytearray(blob)
        b[16] ^= 0x01
        blob = bytes(b)
    info = {"status": vm.get("status"), "steps": vm.get("steps"),
            "second": second, "region": reg, "n_claims": len(claims),
            "desc10_len": meta["desc10_padded"],
            "unpadded": meta["desc10_unpadded"],
            "flipped": flip_bit, "kind": kind}
    return blob, info


def auth(blob):
    return fc._auth_header(blob)


# ---------------------------------------------------------------------------
# Request builders (mirror api_session / api_sdk_click / api_attribution, but
# with FRESH-REGION signatures).
# ---------------------------------------------------------------------------
def _finish(p, dev_swap=True):
    p.update(fc.DEV)
    p.pop("no_sim", None)
    if fc.DEV.get("no_sim"):
        p.pop("mcc", None)
        p.pop("mnc", None)
    # CORRECTION: the genuine NON-ORGANIC click (saz _saz_x/raw/2_c.txt, GAID
    # d016e7e4, tracker 24pxw9rl) carries click_time, click_time_server,
    # install_begin_time, install_begin_time_server and install_version --
    # 47 wire keys.  The earlier "0 hits in the device capture" note covered
    # only the ORGANIC captures, and stripping these was wrong.  They are
    # wire-only: desc10_keys('click') signs 32 keys and none of these five, so
    # they do not change the envelope.
    if p.get("source") == "install_referrer":
        p.setdefault("google_play_instant", "0")
        p.setdefault("install_version", fc.DEV.get("app_version", "3.13.9"))
    else:
        p.pop("install_version", None)   # session carries none
    return p


def build_session(gps, auid, ins, second):
    p = dict(S1P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": fc.fmt(second - 1, 928).decode(),
              "sent_at": fc.fmt(second - 1, 942).decode(),
              "installed_at": ins, "updated_at": ins})
    return _finish(p)


def build_sdk_click(gps, auid, referrer, t_track, tb, ins, second):
    p = dict(S2P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": fc.fmt(second - 1, 961).decode(),
              "sent_at": fc.fmt(second - 1, 970).decode(),
              "installed_at": ins,
              "updated_at": ins,
              "referrer": referrer, "source": "install_referrer",
              "referrer_api": "google",
              # Timing relations measured from the genuine non-organic record:
              #   *_server == device value - 2s
              #   install_begin_time == installed_at - 7s
              "click_time": fc.fmt(t_track, 0).decode(),
              "click_time_server": fc.fmt(t_track - 2, 0).decode(),
              "install_begin_time": fc.fmt(tb, 0).decode(),
              "install_begin_time_server": fc.fmt(tb - 2, 0).decode()})
    return _finish(p)


def build_attribution(gps, auid, second):
    p = {"initiated_by": "backend", "gps_adid_attempt": "1",
         "api_level": fc.DEV["api_level"],
         "app_version": fc.DEV["app_version"], "app_token": APP_TOKEN,
         "os_version": fc.DEV["os_version"],
         "created_at": fc.fmt(second - 1, 666).decode(), "device_type": "phone",
         "gps_adid": gps, "foreground": "1", "android_uuid": auid,
         "sent_at": fc.fmt(second - 1, 696).decode(),
         "offline_mode_enabled": "0", "device_name": fc.DEV["device_name"],
         "environment": "production", "needs_response_details": "1",
         "attribution_deeplink": "1", "package_name": "com.penti.app",
         "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
         "tracking_enabled": "1"}
    return p


# ---------------------------------------------------------------------------
# Self-checks (network-free).
# ---------------------------------------------------------------------------
def self_check(gps, auid):
    second = int(time.time()) - 2
    ins = fc.fmt(second - 170, 774).decode()
    t_track = second - 40
    tb = t_track + CTIT

    out = {}
    # 1. session mint: laws + shape + header + remint-identical
    #    (pin V so the remint is byte-deterministic; live mints use fresh V)
    pinned_V = (int(second) ^ 12345) & 0xFFFFFFFF
    ps = build_session(gps, auid, ins, second)
    b1, i1 = mint_signed("session", ps, second, V=pinned_V)
    b1b, i1b = mint_signed("session", ps, second, V=pinned_V)
    d0b, d2b, d4b, reg = fresh_region(second, V=pinned_V)
    laws = MP.region_laws(d0b, d4b)
    out["session_len_192"] = (len(b1) == 192)
    out["session_header_law"] = (b1[:16] == fc.make_header(second))
    out["region_laws"] = laws
    out["region_valid"] = all(laws[k] for k in
                              ("L1_tile_Rrep", "L2_d4_6_hi_eq_R", "L3_X_eq_U3"))
    out["session_remint_identical"] = (b1 == b1b)
    out["session_status"] = i1["status"]
    out["session_desc10_len"] = i1["desc10_len"]
    # 2. sdk_click mint carries the click claims
    ref = ("adjust_reftag=cYSGT8JtP0ABu&utm_source=VKM+Digital+Yeni"
           "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")
    pc = build_sdk_click(gps, auid, ref, t_track, tb, ins, second)
    bc, ic = mint_signed("click", pc, second)
    out["click_len_192"] = (len(bc) == 192)
    out["click_claims_present"] = all(
        k in MP.claims_from_wire(pc, "click")
        for k in ("referrer", "referrer_api", "source", "session_count"))
    out["click_referrer_in_wire"] = ("adjust_reftag=" in pc["referrer"])
    out["click_source_install_referrer"] = (pc["source"] == "install_referrer")
    out["click_desc10_len"] = ic["desc10_len"]
    # 3. attribution mint
    pa = build_attribution(gps, auid, second)
    ba, ia = mint_signed("attribution", pa, second)
    out["attr_len_192"] = (len(ba) == 192)
    out["attr_claims_n"] = ia["n_claims"]
    # 4. bit-flip actually differs by exactly one bit (same pinned V)
    bf, _ = mint_signed("session", ps, second, V=pinned_V, flip_bit=True)
    out["bitflip_differs"] = (bf != b1)
    out["bitflip_one_bit"] = (sum(bin(x ^ y).count("1")
                                  for x, y in zip(bf, b1)) == 1)
    out["fresh_gaid"] = gps
    out["fresh_auid"] = auid
    return out


# ---------------------------------------------------------------------------
# One funnel attempt on a FRESH GAID.
# ---------------------------------------------------------------------------
def run_attempt(idx, send_live=False, flip_session=False):
    gps = str(uuid.uuid4())        # FRESH GAID, never the device's
    auid = str(uuid.uuid4())       # FRESH android_uuid
    rec = {"idx": idx, "gps": gps, "auid": auid,
           "flip_session_bit": flip_session, "steps": {}}

    # --- the click: stamp gps_adid on the tracker link, follow to reftag ---
    link = __import__("click_bind_chain").expand(LINK, gps)
    t_click = int(time.time())
    code, ref, hops = __import__("click_bind_chain").tracker_click(link, gps)
    rec["click"] = {"http": code, "referrer": ref,
                    "t_click": t_click, "hops": hops}
    if not ref or "adjust_reftag=" not in ref:
        rec["verdict"] = "NO_REFTAG"
        return rec
    if not send_live:
        rec["verdict"] = "DRY_RUN (no traffic sent)"
        return rec

    tb = t_click + CTIT
    ins = fc.fmt(tb + INS_LAG, 431).decode()

    # --- /session (fresh-region signature; optionally bit-flipped) ---
    sec_s = int(time.time()) - 2
    ps = build_session(gps, auid, ins, sec_s)
    bs, isig = mint_signed("session", ps, sec_s, flip_bit=flip_session)
    rec["steps"]["session"] = {"info": isig}
    s, r = fc.send("https://app.adjust.com/session", ps, bs)
    rec["steps"]["session"]["http"] = s
    rec["steps"]["session"]["resp"] = r[:800]

    # --- /sdk_click (fresh-region signature, carries the reftag) ---
    sec_c = int(time.time()) - 2
    pc = build_sdk_click(gps, auid, ref, t_click, tb, ins, sec_c)
    bc, ic = mint_signed("click", pc, sec_c)
    rec["steps"]["sdk_click"] = {"info": ic}
    s, r = fc.send("https://app.adjust.com/sdk_click", pc, bc)
    rec["steps"]["sdk_click"]["http"] = s
    rec["steps"]["sdk_click"]["resp"] = r[:800]

    # make sure the install timeline is in the past
    wait = (tb + INS_LAG + 3) - int(time.time())
    if wait > 0:
        time.sleep(wait)

    # --- /attribution poll (fresh-region signature) ---
    polls = []
    for k in range(3):
        sec_a = int(time.time()) - 2
        pa = build_attribution(gps, auid, sec_a)
        ba, ia = mint_signed("attribution", pa, sec_a)
        s, r = fc.send("https://app.adjust.com/attribution", pa, ba, method="GET")
        polls.append({"http": s, "resp": r[:2000], "info": ia})
        if k < 2:
            time.sleep(15)
    rec["steps"]["attribution"] = polls
    rec["verdict"] = score(polls)
    return rec


def score(polls):
    last = polls[-1]["resp"]
    try:
        a = json.loads(last)["attribution"]
    except Exception:
        return "PARSE_FAIL: " + last[:200]
    net = a.get("network")
    tok = a.get("tracker_token")
    if net and net != "Organic":
        return "NON_ORGANIC %s / %s / eng=%s" % (tok, net,
                                                 a.get("engagement_time"))
    return "ORGANIC %s / eng=%s" % (tok, a.get("engagement_time"))


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attempts", type=int, default=1,
                    help="valid (V) cells to run")
    ap.add_argument("--send", action="store_true",
                    help="actually send (registers real clicks on the campaign)")
    ap.add_argument("--confirm", default="",
                    help="must equal SEND-OFFLINE-FRESHREGION to send")
    ap.add_argument("--skip-control", action="store_true",
                    help="skip the bit-flip negative-control cell")
    args = ap.parse_args()

    send_live = bool(args.send and args.confirm == "SEND-OFFLINE-FRESHREGION")
    if args.send and not send_live:
        print("!! --send given without the exact --confirm token; forcing dry-run.")

    # ---- self-checks (always, network-free) ----
    probe_gps, probe_auid = str(uuid.uuid4()), str(uuid.uuid4())
    sc = self_check(probe_gps, probe_auid)
    print("=== SELF-CHECKS (network-free) ===")
    for k, v in sc.items():
        print("  %-28s %s" % (k, v))
    must = ["session_len_192", "session_header_law", "region_valid",
            "session_remint_identical", "click_len_192",
            "click_claims_present", "click_referrer_in_wire",
            "click_source_install_referrer", "attr_len_192",
            "bitflip_differs", "bitflip_one_bit"]
    bad = [k for k in must if not sc.get(k)]
    if bad:
        print("!! SELF-CHECK FAILED:", bad)
        return 2
    print("  -> all structural self-checks GREEN\n")

    plan = {"mode": "SEND" if send_live else "DRY-RUN",
            "identity": "fresh GAID + fresh android_uuid per cell",
            "valid_cells": args.attempts,
            "control_cell": (not args.skip_control),
            "tracker": LINK[:70] + "..."}
    print("=== PLAN ===")
    print("  mode        :", plan["mode"])
    print("  valid cells :", args.attempts, " (fresh region, full funnel)")
    print("  control     :", "1 bit-flipped /session (negative control)"
          if not args.skip_control else "SKIPPED")
    print("  NOTE: sending registers REAL clicks on the live VKM campaign.\n")

    if not send_live:
        print("=== DRY-RUN: mints only, no traffic. Use --send --confirm "
              "SEND-OFFLINE-FRESHREGION to go live. ===")
        # exercise one dry attempt to prove the click binding works end to end
        rec = run_attempt(0, send_live=False)
        print("  click http=%s reftag=%s" % (
            rec["click"]["http"],
            (rec["click"]["referrer"] or "").split("&")[0]))
        return 0

    # ---- LIVE ----
    results = []
    for i in range(args.attempts):
        print("=== attempt %d (VALID cell, fresh GAID) ===" % i, flush=True)
        r = run_attempt(i, send_live=True, flip_session=False)
        print("  VERDICT:", r["verdict"], flush=True)
        results.append(r)
    if not args.skip_control:
        print("=== attempt C (NEGATIVE CONTROL, bit-flipped /session) ===",
              flush=True)
        rc = run_attempt(99, send_live=True, flip_session=True)
        print("  VERDICT:", rc["verdict"], flush=True)
        results.append(rc)

    json.dump(results, open(OUT, "w"), indent=1)
    print("\n=== SUMMARY ===")
    for r in results:
        print("  [%s] gps=%s -> %s" % (r["idx"], r["gps"][:8], r["verdict"]))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
