"""oneclick.py — paste a LINK + DEVICE below, run it. Done.

    1) edit the CONFIG block at the top (paste your link + your device json)
    2) python oneclick.py

It fires:  click -> /session -> /sdk_click -> /attribution (x3)
All three calls are signed by the REAL mint (mint_pipeline -> F.py -> FinEx VM).
The verdict is the attribution response's engagement_time.
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

# ======================= PASTE YOUR VALUES HERE =======================

LINK = (
    "https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
    "&creative=penti_generic&click_id={click_id}&idfa={click_id}"
    "&gps_adid={click_id}"
    # "&install_callback=...&event_callback_...=..."   # optional: keep if your link has them
)

# Paste your full device json (the big {...} object) here, as a dict.
DEVICE = {
    "kernel": "15",
    "locale": {"country": "IN", "language": "en"},
    "ram": {"available": "3472", "shown": "8112"},
    "os_incremental": "a4cca-aa81e10",
    "bluetooth": "3.0",
    "hardware": "",
    "imei": "861828082457237",
    "cpu_core": "7",
    "private_ip": "10.0.77.186",
    "device_type": "phone",
    "timezone": "+0530",
    "serial": "7376bc9da66ba8e5",
    "mnc": "863",
    "android_id": "db8a74a818d55dde",
    "cpu_arch": "aarch64",
    "display_metrics": {"ypx": "720", "screen_layout_name": "large",
                        "screen_layout_format": "long", "xpx": "1600",
                        "ydp": 278.53, "xdp": 278.552, "aspect_ratio": "10:4",
                        "density_dpi": "xhdpi", "screen_layout_size": 3},
    "last_rebooted_at": 1790089703741,
    "network_band": "LTE",
    "cpu_abi2": "",
    "User-Agent": "Mozilla/5.0 (Linux; Android 15; moto g34 5G) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/154.0.8037.49 Mobile Safari/537.36",
    "cpu_frequency": {"max": "1804.0", "min": "300.0"},
    "os_version": "15",
    "build": "V1UG35H.75-14",
    "gpu": {"version": "ARM", "vendor": "ARM", "name": "Immortalis-G925",
            "opengl_version": "262400"},
    "build_prop": {"dalvik_vm_isa_x86_features": "",
                   "dalvik_vm_isa_x86_variant": "",
                   "dalvik_vm_isa_arm_variant": "cortex-a75",
                   "dalvik_vm_isa_arm64_features": "default",
                   "dalvik_vm_isa_arm64_variant": "kryo300",
                   "dalvik_vm_isa_arm_features": "default",
                   "ro_build_user": "hudsoncm"},
    "manufacturer": "motorola",
    "subAgent": "ol303e83fo39nlw217",
    "local_tz": "IST",
    "product": "fogos_g",
    "brand": "motorola",
    "screen_size": "6.3",
    "mcc": "405",
    "device_id": "fc630573-cad1-4ac5-a425-82dc24fb4b0b",
    "mac": "ce:14:6c:e1:a1:04",
    "adid": "fc630573-cad1-4ac5-a425-82dc24fb4b0b",
    "apps_count": {"user_apps": 46, "sideloaded_apps": 10, "stock_apps": 216},
    "fingerprint": "motorola/fogos_g/fogos:15/V1UG35H.75-14/a4cca-aa81e10:user/release-keys",
    "device": "fogos",
    "sensors": {
        "magnetometer": {"vendor": "memsic", "name": "mmc56x3x Magnetometer Wakeup"},
        "gyroscope": {"vendor": "TDK-Invensense", "name": "icm4x6xa Gyroscope Wakeup"},
        "accelerometer": {"vendor": "TDK-Invensense", "name": "icm4x6xa Accelerometer Wakeup"}},
    "sdk": "35",
    "name": "fogos",
    "currency": {"code": "INR", "name": "Indian Rupee"},
    "mainboard": "fogos",
    "country": "India",
    "local_timezone": "Indian Standard Time",
    "processor": "AArch64 Processor rev 4 (aarch64)",
    "network": "WiFi",
    "carrier": "Jio",
    "os_codename": "REL",
    "cpu_abi": "arm64-v8a",
    "internal_memory": {"available": "111.19 GB", "shown": "128 GB"},
    "model": "moto g34 5G",
    "local_tz_name": "Asia/Kolkata",
    "resolution": "720x1600",
    "display": "V1UG35H.75-14",
    "dpi": "280",
}

# ---------------------------------------------------------------------------
# MODE A (default) — "FULL LINK": paste LINK below, script fires the click.
#
# MODE B — "ALREADY CLICKED": you already fired the click on a real device and
#   you have that click's device json + its referrer. Paste BOTH:
#     * DEVICE  = that same clicked device's json (below)
#     * REFERRER = the referrer that click returned, e.g.
#                  "adjust_reftag=XXXX&adj_click_type=Click&..."
#     * GAID    = that device's GAID (optional — if you leave it "" the script
#                 takes it from DEVICE["adid"], so just paste the device json)
#   and the script SKIPS the click and runs the install on that referrer+GAID.
#   Set REFERRER to anything non-empty to enter MODE B.
# ---------------------------------------------------------------------------
REFERRER = "adjust_reftag=TESTreftag123&adj_click_type=Click&adjust_campaign=AH"   # MODE B: paste "adjust_reftag=...&..." to SKIP the click and use this
GAID = "11111111-2222-3333-4444-555555555555"       # MODE B: paste the clicked device's GAID ("" = read DEVICE["adid"])
CLICK_AGO = 60   # MODE B: real seconds since that click fired (0 = install now)
POLLS = 3       # how many times to poll /attribution
DRY = True     # True = build & check everything, send nothing

# ======================================================================

CTIT = 217.431        # click -> installed_at (the winning device's CTIT)
CTIT_BEGIN = 210.0   # click -> install_begin_time
OUT = os.path.join(HERE, "oneclick_result.json")
# The real app sends the PLAY install referrer here, not the tracking URL.
PLAY_REFERRER = "utm_source=(not%20set)&utm_medium=(not%20set)"


def txt(r):
    return r.decode("utf-8", "replace") if isinstance(r, bytes) else r


# ---- profile from the pasted device json -------------------------------
FC.DEV = RF.dev_from_json(DEVICE)
FC.UA = RF.ua_from_json(DEVICE)
tz = (DEVICE.get("timezone") or "+0530").strip()
sgn = -1 if tz.startswith("-") else 1
d = tz.lstrip("+-")
FC.OFF_MINUTES, FC.OFF_LABEL = sgn * (int(d[:2]) * 60 + int(d[2:4])), tz
FC.ADD_IDFA = False
FC.USE_PROXY = False

if DRY:
    def _dry_send(url, params, blob, method="POST"):
        print("  [dry] would %s %s  params=%d blob=%dB"
              % (method, url.split("?")[0], len(params), len(blob)), flush=True)
        return 200, json.dumps({"app_token": FC.APP_TOKEN,
                                "adid": "0" * 32, "ask_in": 2000})
    FC.send = _dry_send

# ---- ids ---------------------------------------------------------------
# MODE B: the GAID comes from the clicked device's own json unless pinned.
gps = GAID or (DEVICE.get("adid") or DEVICE.get("device_id") or "") \
    or str(uuid.uuid4())
auid = str(uuid.uuid4())
link = LINK.replace("{click_id}", gps).replace("{sub3}", gps)
MODE = "B (already clicked: referrer + GAID)" if REFERRER else "A (full link)"

res = {"gps": gps, "auid": auid, "ua": FC.UA, "tz": tz, "mode": MODE,
       "dev": FC.DEV, "polls": POLLS, "dry": DRY}

print("=" * 60)
print(" MODE     : %s" % MODE)
print(" gps/GAID : %s%s" % (gps, "" if (GAID or REFERRER) else "  (fresh)"))
print(" android  : %s" % auid)
print(" device   : %s / Android %s / api %s"
      % (FC.DEV["device_name"], FC.DEV["os_version"], FC.DEV["api_level"]))
print(" tz       : %s   mcc/mnc: %s/%s"
      % (tz, FC.DEV.get("mcc", "-"), FC.DEV.get("mnc", "-")))
print(" signer   : real mint (F.py region + FinEx VM)")
print("=" * 60)

# ---- step 1: click ------------------------------------------------------
# In MODE B the click already happened; CTIT is measured from THAT click, so
# the user can set CLICK_AGO to the real seconds elapsed since it fired.
t_click = time.time() - (float(CLICK_AGO) if REFERRER else 0.0)
if DRY:
    referrer = REFERRER or "adjust_reftag=DRYRUN&utm_source=dry"
    print("\nSTEP 1/4 click SKIPPED (DRY)")
elif REFERRER:
    referrer = REFERRER
    print("\nSTEP 1/4 click SKIPPED (MODE B — using your pasted referrer)")
    print("  reftag: %s" % referrer[:140])
else:
    print("\nSTEP 1/4 click...")
    click_dev = {"locale": DEVICE.get("locale") or {},
                 "User-Agent": DEVICE.get("User-Agent") or FC.UA,
                 "os_version": DEVICE.get("os_version", "15"),
                 "model": DEVICE.get("model", ""),
                 "build": DEVICE.get("build", "")}
    referrer, _ = RF.click_tracker(link, gps, FC.UA, click_dev)
    print("  reftag: %s" % (referrer or "")[:140])
    if "adjust_reftag=" not in (referrer or ""):
        print("!! tracker gave no adjust_reftag — check LINK"); sys.exit(1)
res["referrer"] = referrer

# ---- wait real CTIT -----------------------------------------------------
# MODE A: the click just fired, so wait out the real CTIT before installing.
# MODE B: the click already happened; CTIT is in the past, so no waiting —
#         install now, and back-date installed_at to click_time + CTIT.
wait = (t_click + CTIT) - time.time()
if wait > 0 and not DRY:
    print("\n  waiting %.0fs for CTIT..." % wait, flush=True)
    time.sleep(wait)
ins = FC.fmt(int(t_click) + int(CTIT), 431)
tb = t_click + CTIT_BEGIN
if REFERRER and not DRY:
    print("  MODE B: install now; installed_at = click + %.0fs (CTIT)"
          % CTIT)

# ---- step 2: /session ---------------------------------------------------
print("\nSTEP 2/4 /session (real mint)...", flush=True)
s2, r2 = M.api_session_mint(gps, auid, ins)
r2 = txt(r2)
print("  -> %s %s" % (s2, r2[:200]), flush=True)
res["session"] = [s2, r2[:600]]
if not DRY:
    time.sleep(3)

# ---- step 3: /sdk_click -------------------------------------------------
print("\nSTEP 3/4 /sdk_click (real mint)...", flush=True)
s1, r1 = M.api_sdk_click_mint(gps, auid, PLAY_REFERRER, int(t_click), tb, ins)
r1 = txt(r1)
print("  -> %s %s" % (s1, r1[:200]), flush=True)
res["sdk_click"] = [s1, r1[:800]]
json.dump(res, open(OUT, "w"), indent=1)

if DRY:
    print("\nDRY: nothing sent. done."); sys.exit(0)

# ---- step 4: /attribution x N -----------------------------------------
try:
    ask = max(json.loads(r2).get("ask_in", 0) or 0,
              json.loads(r1).get("ask_in", 0) or 0)
except Exception:
    ask = 0
ib = "backend" if ask else "sdk"
wait = min(ask / 1000.0, 180.0)
print("\nSTEP 4/4 /attribution x%d (initiated_by=%s, ask_in=%sms)"
      % (POLLS, ib, ask), flush=True)
if wait > 0:
    print("  sleeping %.0fs..." % wait, flush=True)
    time.sleep(wait)

verdicts = []
for i in range(POLLS):
    st, body = M.api_attribution_mint(gps, auid, "pt-" + auid[:8], ib)
    body = txt(body)
    try:
        a = json.loads(body).get("attribution", {})
    except Exception:
        a = {}
    eng = a.get("engagement_time")
    joined = bool(eng) and not eng.startswith("0001-01-01")
    print("  poll %d/%d %s token=%s network=%s eng=%s => %s"
          % (i + 1, POLLS, st, a.get("tracker_token"), a.get("network"), eng,
             "JOINED" if joined else "organic"), flush=True)
    verdicts.append({"status": st, "token": a.get("tracker_token"),
                     "network": a.get("network"), "engagement_time": eng,
                     "joined": joined, "installed_at": a.get("installed_at"),
                     "raw": body[:1200]})
    res.setdefault("polls_raw", []).append([st, body[:1200]])
    if i + 1 < POLLS:
        time.sleep(20)

res["JOINED"] = any(v["joined"] for v in verdicts)
json.dump(res, open(OUT, "w"), indent=1)
print("\n" + "=" * 60)
print(" VERDICT: %s" % ("NON-ORGANIC — click joined" if res["JOINED"]
                        else "Organic"))
print("=" * 60)
print("saved", OUT)
