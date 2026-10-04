# via_device_test.py - verify the DEVICE transport (`adb shell curl`) end-to-end
# with one signed call. Isolates the transport variable: same signature bytes,
# different IP/TLS stack (the phone's, not this PC's).
import json
import os
import sys
import time
import uuid

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
sys.path.insert(0, HERE)
import adj9_full_chain as F
import run_funnel as R

dev = json.load(open(os.path.join(HERE, "dev_mi.json"), encoding="utf-8"))
F.DEV, F.UA = R.dev_from_json(dev), R.ua_from_json(dev)
_tz = (dev.get("timezone") or "+0530").strip()
F.OFF_MINUTES = (int(_tz[1:3]) * 60 + int(_tz[3:5])) * (
    -1 if _tz[0] == "-" else 1)
F.OFF_LABEL = _tz
F.USE_DEVICE = True
F.ADD_IDFA = False

gps = getattr(F, "ADID", None) or getattr(F, "GPS", None) or str(uuid.uuid4())
auid = str(uuid.uuid4())
sec = int(time.time())
ins = F.fmt(sec - 20, 431)
print("transport DEVICE (adb curl); gps=%s auid=%s" % (gps, auid), flush=True)
s, r = F.api_session(gps, auid, ins)
print("SESSION via device ->", s, str(r)[:300], flush=True)
s2, r2 = F.api_attribution(gps, auid, "e" + "x" * 60, "sdk")
print("ATTR via device    ->", s2, str(r2)[:300], flush=True)
json.dump({"gps": gps, "auid": auid, "session": [s, str(r)[:2000]],
           "attr": [s2, str(r2)[:2000]]},
          open(os.path.join(HERE, "via_device_result.json"), "w"), indent=1)
print("saved via_device_result.json")