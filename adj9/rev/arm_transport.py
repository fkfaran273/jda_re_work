"""arm_transport.py — isolate TRANSPORT as the attribution discriminator.

Setup identical to arm_c_corrected (moto g42 profile, real CTIT, real mint),
with ONE variable changed: all three signed calls are transported by the DEVICE
via `send_device` (adb shell curl) instead of this PC. So the calls leave from
the phone's egress IP (146.196.32.6, Excitel, India) and the phone's TLS stack
rather than the PC's (106.219.162.214, Airtel, India + Python OpenSSL).

Both egresses are Indian residential ISPs, so this mainly isolates the TLS /
HTTP fingerprint. The click still fires from the PC to create the server-side
click record (click is keyed to gps_adid, independent of source IP).

Verdict = attribution engagement_time. Nonzero => click joined.
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
OUT = os.path.join(HERE, "arm_transport_result.json")

FC.DEV = dict(PROFILE["DEV"])
FC.UA = PROFILE["UA"]
FC.OFF_MINUTES, FC.OFF_LABEL = PROFILE["OFF_MINUTES"], PROFILE["OFF_LABEL"]
FC.ADD_IDFA = PROFILE["ADD_IDFA"]
FC.USE_PROXY = False
FC.USE_DEVICE = True          # <-- the single changed variable

res = {"arm": "transport (device-sent)", "ctit_install": CTIT_INSTALL,
       "transport": "DEVICE (adb shell curl)"}

gps, link = M._fresh_gps_link(RF.LINK)
auid = str(uuid.uuid4())
res["gps"], res["auid"] = gps, auid
print("[arm-T] fresh gps=%s auid=%s" % (gps, auid), flush=True)
print("[arm-T] transport = DEVICE for all 3 signed calls", flush=True)

CLICK_DEV = {
    "locale": {"language": "tr", "country": "TR"},
    "User-Agent": FC.UA,
    "os_version": PROFILE["DEV"]["os_version"],
    "model": PROFILE["DEV"]["device_name"],
    "build": PROFILE["DEV"]["os_build"],
    "mcc": "", "mnc": "",
}

# STEP 1 — click from PC to create the click record for this gps_adid.
t_click = time.time()
ref, hop = RF.click_tracker(link, gps, FC.UA, CLICK_DEV)
print("[arm-T] STEP 1/4 click hop=%s" % str(hop)[:80], flush=True)
assert ref and "adjust_reftag=" in ref, "tracker gave no referrer"
res["reftag"] = ref.split("adjust_reftag=", 1)[1].split("&")[0]
print("[arm-T] reftag=%s" % res["reftag"], flush=True)

# STEP 2 — wait real CTIT.
wait = CTIT_INSTALL - (time.time() - t_click)
if wait > 0:
    print("[arm-T] STEP 2/4 waiting %.0fs for CTIT..." % wait, flush=True)
    time.sleep(wait)

ins = FC.fmt(int(t_click) + int(CTIT_INSTALL), 431)
tb = t_click + CTIT_BEGIN

# STEP 3 — mint-signed session, transported by the DEVICE.
print("[arm-T] STEP 3/4 session (device-sent)...", flush=True)
s2, r2 = M.api_session_mint(gps, auid, ins)
print("[arm-T] SESSION: %s %s" % (s2, r2[:200]), flush=True)
res["session"] = [s2, r2[:400]]
json.dump(res, open(OUT, "w"), indent=1)
time.sleep(3)

# STEP 4 — mint-signed sdk_click, transported by the DEVICE.
PLAY_REFERRER = "utm_source=(not%20set)&utm_medium=(not%20set)"
print("[arm-T] STEP 4/4 sdk_click (device-sent)...", flush=True)
s1, r1 = M.api_sdk_click_mint(gps, auid, PLAY_REFERRER, int(t_click), tb, ins)
print("[arm-T] SDK_CLICK: %s %s" % (s1, r1[:200]), flush=True)
res["sdk_click"] = [s1, r1[:600]]
json.dump(res, open(OUT, "w"), indent=1)

# VERDICT — attribution poll, device-sent, real mint.
print("[arm-T] polling attribution (device-sent)...", flush=True)
time.sleep(5)
st, body = M.api_attribution_mint(gps, auid, "pt-" + auid[:8])
res["poll"] = [st, body[:1500]]
print("[arm-T] poll %s %s" % (st, body[:600]), flush=True)

try:
    a = json.loads(body).get("attribution", {})
    res["verdict"] = a
    eng = a.get("engagement_time")
    print("\n=== VERDICT (arm-T transport) ===")
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
