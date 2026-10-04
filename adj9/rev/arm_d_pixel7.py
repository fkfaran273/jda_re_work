"""arm_d_pixel7.py — live arm on the ALREADY-CLICKED Pixel 7 Pro GAID.

This is the one lever arm C could not test: a real Adjust click already exists
server-side for GAID 8e39efb6-5260-435d-9d08-2e81b3817698, carrying reftag
cBY97SSI6u6Kx.  Arm C sent a synthetic click and got Organic; here we install
against a click that genuinely happened.

Differences from arm C (moto g42):
  * different device entirely: Pixel 7 Pro / Android 16 / api 36 / cheetah
  * this device HAS a SIM -> mcc=286, mnc=01 ARE sent (moto sent neither)
  * referrer is the REAL reftag, not the "(not set)" placeholder
  * timezone +0200 (device-reported), not +0530
  * NO new click is fired and NO new GAID is minted — the click already exists

The connected device is never touched. No adb anywhere in this file.

CLICK_AGE_SEC: how long ago the already-made click happened. We were not told,
so it defaults to 0 (treat the click as having just landed) and is logged
loudly. The server matches on its own click timestamp; this only shapes the
declared CTIT we report.
"""
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mint_pipeline as M
import run_funnel as RF
import adj9_full_chain as FC

# ---------------------------------------------------------------- device ---
CFG = json.load(open(os.path.join(HERE, "pixel7_click.json")))
DEV_JSON = CFG["DEV_JSON"]

# The GAID the click was already made with.  DO NOT regenerate this.
GPS = CFG["GPS"]
REFERRER = CFG["REFERRER"]
REFTAG = CFG["REFTAG"]

CTIT_INSTALL = CFG["CTIT_INSTALL"]
CTIT_BEGIN = CFG["CTIT_BEGIN"]
CLICK_AGE_SEC = CFG["CLICK_AGE_SEC"]   # unknown; assume the click just landed
OUT = os.path.join(HERE, "mint_arm_d_result.json")

# ----------------------------------------------------------------- setup ---
FC.DEV = RF.dev_from_json(DEV_JSON)      # no no_sim -> mcc/mnc stay on the wire
FC.UA = RF.ua_from_json(DEV_JSON)
FC.OFF_MINUTES, FC.OFF_LABEL = CFG["OFF_MINUTES"], CFG["OFF_LABEL"]
FC.ADD_IDFA = False
FC.USE_PROXY = False

# extra wire fields this device reports that the moto template lacked
FC.S2P = dict(FC.S2P)
FC.S2P.update({"screen_format": "long", "connectivity_type": "1"})

auid = str(uuid.uuid4())
t_track = time.time() - CLICK_AGE_SEC

res = {"arm": "D", "device": "Pixel 7 Pro / Android 16 / api 36",
       "gps": GPS, "click_already_made": True, "new_click_fired": False,
       "referrer": REFERRER, "reftag": REFTAG,
       "click_age_assumed_sec": CLICK_AGE_SEC,
       "off_label": FC.OFF_LABEL, "off_minutes": FC.OFF_MINUTES}

print("[arm-d] GAID (pre-clicked, reused): %s" % GPS, flush=True)
print("[arm-d] NO new click, NO new GAID — the click already exists", flush=True)
print("[arm-d] referrer/reftag: %s" % REFTAG, flush=True)
print("[arm-d] DEV: %s" % json.dumps(FC.DEV, sort_keys=True), flush=True)
print("[arm-d] UA : %s" % FC.UA, flush=True)
print("[arm-d] tz : %+d min label %s" % (FC.OFF_MINUTES, FC.OFF_LABEL), flush=True)
print("[arm-d] mcc/mnc ON the wire: %s / %s"
      % (FC.DEV.get("mcc"), FC.DEV.get("mnc")), flush=True)
print("[arm-d] android_uuid (fresh per-install): %s" % auid, flush=True)

# ------------------------------------------------- install timing shape ----
wait = (t_track + CTIT_INSTALL) - time.time()
if wait > 0:
    print("[arm-d] waiting %.0fs to reproduce the 217.431s CTIT..." % wait,
          flush=True)
    time.sleep(wait)

ins = FC.fmt(int(t_track) + int(CTIT_INSTALL), 431)
tb = t_track + CTIT_BEGIN

# ------------------------------------------------------------- session ----
print("[arm-d] mint-signed /session ...", flush=True)
s2, r2 = M.api_session_mint(GPS, auid, ins)
print("[arm-d] SESSION: %s %s" % (s2, r2[:300]), flush=True)
res["session"] = [s2, r2[:600]]
json.dump(res, open(OUT, "w"), indent=1)
time.sleep(3)

# ------------------------------------------------------------ sdk_click ---
print("[arm-d] mint-signed /sdk_click (real reftag) ...", flush=True)
s1, r1 = M.api_sdk_click_mint(GPS, auid, REFERRER, int(t_track), tb, ins)
print("[arm-d] SDK_CLICK: %s %s" % (s1, r1[:300]), flush=True)
res["sdk_click"] = [s1, r1[:800]]
json.dump(res, open(OUT, "w"), indent=1)

# ---------------------------------------------------------- attribution ---
print("[arm-d] polling /attribution ...", flush=True)
time.sleep(5)
st, body = FC.api_attribution(GPS, auid, "pt-" + auid[:8])
res["poll"] = [st, body[:2000]]
print("[arm-d] poll %s %s" % (st, body[:700]), flush=True)

try:
    a = json.loads(body).get("attribution", {})
    res["verdict"] = a
    eng = a.get("engagement_time")
    print("\n=== VERDICT ===")
    print("tracker_token  : %s" % a.get("tracker_token"))
    print("tracker_name   : %s" % a.get("tracker_name"))
    print("network        : %s" % a.get("network"))
    print("engagement_time: %s" % eng)
    print("installed_at   : %s" % a.get("installed_at"))
    print("first_session  : %s" % a.get("first_session_time"))
    print("reattributed   : %s" % a.get("is_reattributed"))
    joined = bool(eng) and not eng.startswith("0001-01-01")
    print("CLICK JOINED   : %s" % ("YES" if joined else "NO (zero engagement)"))
except Exception as e:
    print("poll parse failed:", e)

json.dump(res, open(OUT, "w"), indent=1)
print("saved", OUT, flush=True)
