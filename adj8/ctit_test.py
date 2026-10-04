"""ctit_test.py — funnel run with a realistic click->install time.

The genuine booking in be_ct_logs_3oct_pxl.chls (Dinos_Dynamic_Partner,
NN102_DNGT) had CTIT ~48 s: click_time 12:03:09 -> installed_at 12:03:57,
session sent 12:04:09.  Our default INSTALL_AFTER is 14 s, which may sit
below this app's fraud threshold.  This run uses a configurable CTIT.

    python ctit_test.py [ctit_seconds] [wait_before_session]
"""
import json
import sys
import time
import uuid

CTIT = int(sys.argv[1]) if len(sys.argv) > 1 else 46
WAIT = int(sys.argv[2]) if len(sys.argv) > 2 else CTIT + 16

sys.argv = [sys.argv[0]]          # run_install parses argv as an app name
sys.path.insert(0, ".")
import run_install as R

R.INSTALL_AFTER = CTIT

gaid = str(uuid.uuid4())
auuid = str(uuid.uuid4())
reftag, _ = R._one_visit(R._subst(R.campaign_data["click_link"], gaid, None))
print("reftag:", reftag, flush=True)
if not reftag:
    raise SystemExit("no reftag")
click_sec = int(time.time())
print("click_sec", click_sec, "target CTIT", CTIT, flush=True)

time.sleep(WAIT)
sec = R.signing_second()
fields = R.build_session_request(gaid, auuid, R.DEVICE, R.campaign_data, sec,
                                 click_sec=click_sec)
print("installed_at:", fields["installed_at"], "| created_at:", fields["created_at"],
      flush=True)
auth, _ = R.sign(fields, "session", sec)
st, body = R.call("POST", "/session", fields, auth)
adid = json.loads(body).get("adid", "")
print("session ->", st, "adid", adid, flush=True)

time.sleep(12)
sec = R.signing_second()
fields = R.build_click_request(gaid, auuid, R.DEVICE, R.campaign_data, sec,
                               reftag, click_sec=click_sec)
auth, _ = R.sign(fields, "click", sec)
print("click_time:", fields["click_time"], "| installed_at:", fields["installed_at"],
      flush=True)
st, body = R.call("POST", "/sdk_click", fields, auth)
print("sdk_click ->", st, body[:140], flush=True)

verdict = {}
for delay in (5, 15, 30, 45, 60, 90):
    time.sleep(delay)
    sec = R.signing_second()
    f = R.build_attribution_request(gaid, auuid, R.DEVICE, R.campaign_data, sec)
    auth, _ = R.sign(f, "attribution", sec)
    st, body = R.call("GET", "/attribution", f, auth)
    v = (json.loads(body).get("attribution") or {})
    verdict = v
    print("poll +%ds -> %s / %s / eng=%s" % (delay, v.get("network"),
                                             v.get("tracker_token"),
                                             v.get("engagement_time")), flush=True)
    if v.get("network") and v["network"] != "Organic":
        print("*** NON-ORGANIC ***", json.dumps(v)[:300], flush=True)
        break

json.dump({"gaid": gaid, "android_uuid": auuid, "adid": adid, "reftag": reftag,
           "click_second": click_sec, "ctit": CTIT, "verdict": verdict},
          open("last_run.json", "w"), indent=1)
print("DONE verdict:", verdict.get("network"), flush=True)
