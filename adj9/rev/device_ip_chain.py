# device_ip_chain.py — THE test the user asked for: our click (marker creative) on
# a fresh GAID, then ALL calls signed by our maker and TRANSPORTED BY THE DEVICE
# (adb curl -> the phone's own IP/TLS). If the click join is honoured for a
# non-app sender, /attribution returns VKM non-organic.
import json
import os
import sys
import time
import uuid

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
sys.path.insert(0, HERE)
import adj9_full_chain as F
import run_funnel as R

OUT = os.path.join(HERE, "device_ip_chain_result.json")
CREATIVE = "cline_devip"

dev = json.load(open(os.path.join(HERE, "dev_mi.json"), encoding="utf-8"))
F.DEV, F.UA = R.dev_from_json(dev), R.ua_from_json(dev)
_tz = (dev.get("timezone") or "+0530").strip()
F.OFF_MINUTES = (int(_tz[1:3]) * 60 + int(_tz[3:5])) * (
    -1 if _tz[0] == "-" else 1)
F.OFF_LABEL = _tz
F.USE_DEVICE = True          # <-- the new transport
F.USE_PROXY = False
F.ADD_IDFA = False

gps = str(uuid.uuid4())
auid = str(uuid.uuid4())
rec = {"gps": gps, "auid": auid, "creative": CREATIVE, "arms": []}
print("GAID:", gps, flush=True)

link = (R.LINK or F.DEFAULT_LINK)
link = link.replace("{click_id}", "clk-" + uuid.uuid4().hex[:12])
link = link.replace("{sub3}", gps)
link = link.replace("creative=penti_generic", "creative=" + CREATIVE)

t_click = time.time()
ref, hop = R.click_tracker(link, gps, F.UA, dev)
print("REFERRER:", ref, flush=True)
rec["referrer"] = ref
if not (ref and "adjust_reftag=" in ref):
    print("no referrer from tracker; aborting"); sys.exit(1)
reftag = ref.split("adjust_reftag=", 1)[1].split("&")[0]

t_begin = int(t_click) + 30           # download begin (CTIT-ish)
ins = F.fmt(t_begin + 7, 431)         # install complete
wait = (t_begin + 7) - time.time()
print("waiting %.0fs so the timeline is plausible..." % wait, flush=True)
if wait > 0:
    time.sleep(wait)

s1, r1 = F.api_session(gps, auid, ins)
print("SESSION:", s1, str(r1)[:200], flush=True)
rec["session"] = [s1, str(r1)[:600]]
try:
    ask = json.loads(r1).get("ask_in", 0) or 0
except Exception:
    ask = 0
if ask:
    w = min(ask / 1000.0, 180.0)
    print("ask_in=%dms -> waiting %.0fs then initiated_by=backend" % (ask, w),
          flush=True)
    time.sleep(w)
ib = "backend" if ask else "sdk"
ptoken = "e" + uuid.uuid4().hex * 3 + ":APA91b" + uuid.uuid4().hex * 3
for i in (1, 2, 3):
    s2, r2 = F.api_attribution(gps, auid, ptoken, ib)
    try:
        a = json.loads(r2).get("attribution", {})
        v = "%s / %s / eng=%s / inst=%s" % (
            a.get("tracker_token"), a.get("network"),
            a.get("engagement_time"), a.get("installed_at"))
    except Exception:
        v = "HTTP %s %s" % (s2, str(r2)[:120])
    print("ATTR%d (via device, %s): %s" % (i, ib, v), flush=True)
    rec["arms"].append({"i": i, "http": s2, "verdict": v,
                        "raw": str(r2)[:1200]})
    if i < 3:
        time.sleep(20)
json.dump(rec, open(OUT, "w"), indent=1)
print("saved", OUT)
