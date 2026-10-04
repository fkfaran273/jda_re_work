r"""crosscheck_run.py — launch com.penti.app with the pinned GAID
(1e63c600-e86b-4e92-a6c3-63846dd6057c) and poll files/AdjustAttribution.

The app signs its own /attribution with a GENUINE blob, so whatever lands in
the file is the server's TRUE verdict for this identity — not a minted-blob
read.
"""
import base64
import json
import re
import subprocess
import sys
import time

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
import crosscheck_device as D

PKG = "com.penti.app"
ATTR = "/data/data/com.penti.app/files/AdjustAttribution"
NEW_GPS = "1e63c600-e86b-4e92-a6c3-63846dd6057c"
DEADLINE = 180  # seconds

out = {"gps": NEW_GPS, "launched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
       "poll": []}

# fresh launch (data already wiped)
r = subprocess.run(["adb", "-s", D.SERIAL, "shell",
                    "monkey -p %s -c android.intent.category.LAUNCHER 1" % PKG],
                   capture_output=True, timeout=60)
print("launch rc=%d" % r.returncode, flush=True)

t0 = time.time()
verdict = None
while time.time() - t0 < DEADLINE:
    time.sleep(5)
    d = D.su_pull(ATTR)
    el = round(time.time() - t0)
    if d:
        txt = d.decode("latin1", "replace")
        m = re.search(r'\{\\?"tracker_token.{0,600}', txt)
        if m:
            verdict = m.group(0)
            print("[%3ds] ATTRIBUTION FOUND: %s" % (el, verdict[:400]), flush=True)
            out["attribution_raw"] = verdict
            out["found_after_s"] = el
            break
        else:
            print("[%3ds] file %d B, no tracker_token yet" % (el, len(d)), flush=True)
    else:
        print("[%3ds] no file yet" % el, flush=True)
    out["poll"].append({"t": el, "size": len(d)})

if verdict is None:
    print("*** TIMEOUT after %ds — no AdjustAttribution content ***" % DEADLINE, flush=True)
    out["timeout"] = True

# classify
if verdict:
    tt = re.search(r'tracker_token\\?":\\?"([a-z0-9]+)', verdict)
    tk = tt.group(1) if tt else "?"
    out["tracker_token"] = tk
    if tk == "wy7261z":
        print("*** VERDICT: ORGANIC (wy7261z) ***", flush=True)
    else:
        print("*** VERDICT: NON-ORGANIC tracker=%s ***" % tk, flush=True)

# logcat evidence
r = subprocess.run(["adb", "-s", D.SERIAL, "logcat", "-d", "-t", "600"],
                   capture_output=True, timeout=60)
adj = [ln for ln in r.stdout.decode("utf-8", "replace").splitlines()
       if re.search(r"Adjust|attribution", ln, re.I)][-25:]
out["logcat_tail"] = adj
for ln in adj:
    print("LOG:", ln[:190], flush=True)

json.dump(out, open(r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\crosscheck_device_result.json", "w"), indent=1)
print("saved crosscheck_device_result.json", flush=True)
