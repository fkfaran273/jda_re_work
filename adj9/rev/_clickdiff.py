import json, os, sys
sys.path.insert(0, os.getcwd())
import mint_pipeline as M
import adj9_full_chain as FC

PROF = json.load(open("moto_g42_profile.json"))
FC.DEV = dict(PROF["DEV"]); FC.UA = PROF["UA"]
FC.OFF_MINUTES, FC.OFF_LABEL = PROF["OFF_MINUTES"], PROF["OFF_LABEL"]

# Rebuild the EXACT click claims arm_transport2 sent (no network).
gps = "52f48449-5f78-41d6-81d8-6823d6f2d61b"
auid = "xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx"  # placeholder, length-equivalent
REF = "utm_source=(not%20set)&utm_medium=(not%20set)"
import time
sec = int(time.time()) + FC.MINT_SKEW
insd = FC.fmt(sec - 170, 774).decode()
p = dict(FC.S2P)
p.update({"gps_adid": gps, "android_uuid": auid,
          "created_at": FC.fmt(sec, 961).decode(),
          "sent_at": FC.fmt(sec, 970).decode(),
          "installed_at": insd, "referrer": REF, "source": "install_referrer",
          "referrer_api": "google",
          "click_time": FC.fmt(sec-400, 0).decode(),
          "click_time_server": FC.fmt(sec-402, 0).decode(),
          "install_begin_time": FC.fmt(sec-190, 0).decode(),
          "install_begin_time_server": FC.fmt(sec-192, 0).decode(),
          "updated_at": insd})
p.update(FC.DEV)
for k in ("no_sim","mcc","mnc"): p.pop(k, None)
val = M.claims_from_wire(p, "click")
V = M.make_V_consistent(sec, 961)
from desc10_law import build_desc10, desc10_keys
raw = build_desc10(val, "click")
print("OUR click d10 len:", len(raw))
print("OUR d10:", raw)
