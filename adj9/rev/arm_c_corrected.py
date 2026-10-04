"""arm_c_corrected.py — live arm using the CORRECTED moto g42 device profile
extracted from the winning non-organic SAZ, with the device's real CTIT shape.

Differences from arm-a (which read Organic with engagement_time=zero):
  * profile = moto_g42_profile.json, not the Redmi DEVICE_JSON
  * mcc/mnc dropped (device sent neither)
  * claim strings reproduce the device exactly: session 360, click 391, attr 246
  * CTIT = 217.431 s click->installed_at (210 s click->install_begin),
    waited for real in wall-clock, not faked in the declared field

Verdict = the attribution response's engagement_time. Nonzero => click joined.
Python-visible, no device required.
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

PROFILE = json.load(open(os.path.join(HERE, "moto_g42_profile.json")))
CTIT_INSTALL = 217.431
CTIT_BEGIN = 210.0
OUT = os.path.join(HERE, "mint_arm_c_result.json")

# Corrected profile, exactly as the winning device sent it.
FC.DEV = dict(PROFILE["DEV"])
FC.UA = PROFILE["UA"]
FC.OFF_MINUTES, FC.OFF_LABEL = PROFILE["OFF_MINUTES"], PROFILE["OFF_LABEL"]
FC.ADD_IDFA = PROFILE["ADD_IDFA"]
FC.USE_PROXY = False

res = {"profile": "moto_g42 (SAZ-corrected)", "ctit_install": CTIT_INSTALL}

gps, link = M._fresh_gps_link(RF.LINK)
auid = str(uuid.uuid4())
res["gps"], res["auid"] = gps, auid
print("[arm-c] fresh gps=%s" % gps, flush=True)
print("[arm-c] profile api=%s os=%s dev=%s mfr=%s lang=%s screen=%sx%s %s"
      % (FC.DEV["api_level"], FC.DEV["os_version"], FC.DEV["device_name"],
         FC.DEV["device_manufacturer"], FC.DEV["language"],
         FC.DEV["display_width"], FC.DEV["display_height"],
         FC.DEV["screen_density"]), flush=True)
print("[arm-c] UA: %s" % FC.UA, flush=True)

# click_tracker wants the full device-JSON shape (locale / model / build).
CLICK_DEV = {
    "locale": {"language": "tr", "country": "TR"},
    "User-Agent": FC.UA,
    "os_version": PROFILE["DEV"]["os_version"],
    "model": PROFILE["DEV"]["device_name"],
    "build": PROFILE["DEV"]["os_build"],
    "mcc": "", "mnc": "",
}

# STEP 1 — real tracker click from the PC, device UA.
t_click = time.time()
ref, hop = RF.click_tracker(link, gps, FC.UA, CLICK_DEV)
print("[arm-c] STEP 1/4 click hop=%s" % str(hop)[:80], flush=True)
print("[arm-c] REFERRER: %s" % (ref or "")[:130], flush=True)
assert ref and "adjust_reftag=" in ref, "tracker gave no referrer"
res["referrer"] = ref
res["reftag"] = ref.split("adjust_reftag=", 1)[1].split("&")[0]

# STEP 2 — wait the device's real CTIT (3.62 min) before the install session.
wait = CTIT_INSTALL - (time.time() - t_click)
if wait > 0:
    print("[arm-c] STEP 2/4 waiting %.0fs for CTIT..." % wait, flush=True)
    time.sleep(wait)

ins = FC.fmt(int(t_click) + int(CTIT_INSTALL), 431)
tb = t_click + CTIT_BEGIN

# STEP 3 — mint-signed session (claims derived from the wire params).
print("[arm-c] STEP 3/4 mint-signed session (corrected profile)...", flush=True)
s2, r2 = M.api_session_mint(gps, auid, ins)
print("[arm-c] SESSION: %s %s" % (s2, r2[:200]), flush=True)
res["session"] = [s2, r2[:400]]
json.dump(res, open(OUT, "w"), indent=1)
time.sleep(3)

# STEP 4 — mint-signed sdk_click. The device's `referrer` is the PLAY install
# referrer, not the tracking URL — click identity rides on the gps-stamped
# tracker click (SAZ session 2 has no adjust_reftag param at all).
PLAY_REFERRER = "utm_source=(not%20set)&utm_medium=(not%20set)"
print("[arm-c] STEP 4/4 mint-signed sdk_click...", flush=True)
s1, r1 = M.api_sdk_click_mint(gps, auid, PLAY_REFERRER, int(t_click), tb, ins)
print("[arm-c] SDK_CLICK: %s %s" % (s1, r1[:200]), flush=True)
res["sdk_click"] = [s1, r1[:600]]
json.dump(res, open(OUT, "w"), indent=1)

# VERDICT — attribution poll. engagement_time is the discriminator.
print("[arm-c] polling attribution...", flush=True)
time.sleep(5)
st, body = FC.api_attribution(gps, auid, "pt-" + auid[:8])
res["poll"] = [st, body[:1500]]
print("[arm-c] poll %s %s" % (st, body[:600]), flush=True)

try:
    a = json.loads(body).get("attribution", {})
    res["verdict"] = a
    eng = a.get("engagement_time")
    print("\n=== VERDICT ===")
    print("tracker_token : %s" % a.get("tracker_token"))
    print("network       : %s" % a.get("network"))
    print("engagement_time: %s" % eng)
    print("installed_at  : %s" % a.get("installed_at"))
    nonzero = eng and not eng.startswith("0001-01-01")
    print("CLICK JOINED  : %s" % ("YES" if nonzero else "NO (zero engagement)"))
except Exception as e:
    print("poll parse failed:", e)

json.dump(res, open(OUT, "w"), indent=1)
print("saved", OUT, flush=True)
