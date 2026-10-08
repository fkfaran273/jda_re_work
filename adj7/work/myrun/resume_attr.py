"""resume_attr.py -- resume the attribution poll for a run whose process was
killed mid-poll (ids read from last_run.json, or --gaid/--adid).

Only the attribution GET is sent (no session/click), so this cannot create a
new install.  The returned adid is checked against the expected one: if it
matches, the verdict belongs to our in-flight install.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_winner as R

DELIBERATE = [2.5, 20, 40, 60]


def main():
    lr = {}
    try:
        lr = json.load(open(os.path.join(HERE, "last_run.json")))
    except Exception:
        pass
    gaid = os.environ.get("FUNNEL_GAID") or lr.get("gaid")
    if not gaid:
        print("no gaid -- pass FUNNEL_GAID or fix last_run.json")
        return 1
    expect_adid = lr.get("adid") or ""
    auuid = lr.get("android_uuid") or ""
    if not auuid:
        # the killed process lost it; gaid is the primary match key, but
        # flag it so the verdict is only trusted if the adid comes back
        auuid = "00000000-0000-4000-8000-000000000000"
        print("WARNING: android_uuid unknown -- trusting the verdict only "
              "if the returned adid == %s" % (expect_adid or "?"))
    print("gaid       %s" % gaid)
    print("expected   adid %s" % (expect_adid or "(unknown)"))

    started = time.time()
    verdict = {}
    for delay in DELIBERATE:
        time.sleep(delay)
        sec = R.signing_second()
        fields = R.build_attribution_request(gaid, auuid, sec)
        auth = R.sign(fields, "attribution", sec)
        status, body = R.call("GET", "/attribution", fields, auth)
        try:
            payload = json.loads(body)
        except Exception:
            print("poll +%ds -> HTTP %d %s" % (delay, status, body[:120]))
            continue
        got_adid = payload.get("adid", "")
        verdict = payload.get("attribution") or {}
        same = (not expect_adid) or (got_adid == expect_adid)
        print("poll +%-4s -> %s / %s  adid=%s match=%s"
              % (delay, verdict.get("network"), verdict.get("tracker_token"),
                 got_adid, same))
        if not same:
            print("   !! adid mismatch -- this verdict is for another "
                  "device; stopping to avoid a false claim")
            return 2
        if verdict.get("network") and verdict["network"] != "Organic":
            break

    print()
    print("FINAL: %s / %s  (%s)" % (verdict.get("network"),
                                    verdict.get("tracker_token"),
                                    verdict.get("tracker_name")))
    for k in ("campaign", "adgroup", "engagement_time", "click_time",
              "installed_at"):
        if verdict.get(k) is not None:
            print("  %-16s %s" % (k, verdict.get(k)))
    json.dump({"gaid": gaid, "expect_adid": expect_adid,
               "verdict": verdict},
              open(os.path.join(HERE, "resume_attr_run.json"), "w"),
              indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
