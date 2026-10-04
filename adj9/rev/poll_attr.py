# poll_attr.py — poll /attribution for a gps/auid, via the device transport.
# usage: python poll_attr.py <gps> <auid> [n]
import json
import os
import sys
import time
import uuid

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_full_chain as F
import run_funnel as R
import mint_session_chain as M

dev = json.load(open(os.path.join(HERE, "dev_mi.json"), encoding="utf-8"))
M.setup_chain(dev)
gps, auid = sys.argv[1], sys.argv[2]
n = int(sys.argv[3]) if len(sys.argv) > 3 else 3
ptoken = "e" + uuid.uuid4().hex * 3 + ":APA91b" + uuid.uuid4().hex * 3
out = []
for i in range(1, n + 1):
    s, r = F.api_attribution(gps, auid, ptoken, "backend")
    try:
        a = json.loads(r).get("attribution", {})
        v = "%s / %s / eng=%s / inst=%s" % (
            a.get("tracker_token"), a.get("network"),
            a.get("engagement_time"), a.get("installed_at"))
    except Exception:
        v = "HTTP %s %s" % (s, str(r)[:200])
    print("ATTR%d: %s" % (i, v), flush=True)
    out.append({"http": s, "verdict": v, "raw": str(r)[:1500]})
    if i < n:
        time.sleep(15)
json.dump({"gps": gps, "auid": auid, "arms": out},
          open(os.path.join(HERE, "poll_attr_result.json"), "w"), indent=1)
print("saved poll_attr_result.json")