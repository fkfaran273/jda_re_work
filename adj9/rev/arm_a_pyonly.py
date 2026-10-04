"""arm_a_pyonly.py — run arm-a's three calls and read the verdict from PYTHON
only.  The device oracle is stubbed out per the user's instruction: nothing is
written to the connected moto g42.

Runs: real tracker click (PC) -> mint-signed session -> mint-signed sdk_click,
then a single Python /attribution poll for whatever the server will show us.

CAVEAT (established twice in this project, slices 92 and 144): a crafted
Python poll returns the silent Organic fallback even when the install record
IS non-organic.  An Organic reading here is therefore NOT proof of failure.
The device app's own AdjustAttribution file is the only trustworthy oracle.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mint_pipeline as M
import run_funnel as RF
import adj9_full_chain as FC

# Do not touch the connected device.
M.device_read_verdict = lambda res, out_path: {
    "skipped": "device oracle disabled (python-only run)",
}

res = M.run_arm_a()

print("\n=== PYTHON-SIDE POLL ===", flush=True)
gps, auid = res["gps"], res["auid"]

dev = json.loads(RF.DEVICE_JSON)
FC.DEV, FC.UA = RF.dev_from_json(dev), RF.ua_from_json(dev)
FC.OFF_MINUTES, FC.OFF_LABEL = 330, "+0530"
FC.ADD_IDFA = False
FC.USE_PROXY = False

st, body = FC.api_attribution(gps, auid, "pt-" + auid[:8])
print("poll status:", st, flush=True)
print("poll body  :", body[:1500], flush=True)
res["python_poll"] = [st, body[:3000]]
json.dump(res, open(os.path.join(HERE, "mint_arm_a_result.json"), "w"), indent=1)

try:
    att = json.loads(body).get("attribution", {})
    tok, net = att.get("tracker_token"), att.get("network")
    print("\nPYTHON READS: tracker_token=%s network=%s" % (tok, net))
    print("non-organic by python read: %s"
          % (tok != M.ORGANIC_TOKEN and net != "Organic"))
    print("NOTE: crafted polls read the Organic fallback even for non-organic")
    print("      records (slices 92/144) — Organic here is inconclusive.")
except Exception as e:
    print("poll parse failed:", e)
