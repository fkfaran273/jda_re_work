# full_chain_devip.py — the COMPLETE forged funnel with the piece every earlier
# chain was missing: /sdk_click carrying the install REFERRER (the join key).
#   click (marker) -> /session -> /sdk_click(source=install_referrer) -> /attr
# All signed by our maker and transported BY THE DEVICE (adb curl).
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

OUT = os.path.join(HERE, "full_chain_devip_result.json")
CREATIVE = "cline_full"


def retry(fn, *a, n=3, **k):
    """Retry a network step; the adb transport blips occasionally."""
    last = None
    for i in range(n):
        try:
            return fn(*a, **k)
        except Exception as e:
            last = e
            print("  [retry %d] %s: %s" % (i + 1, type(e).__name__, str(e)[:120]),
                  flush=True)
            time.sleep(4)
    raise last



def main():
    dev = json.load(open(os.path.join(HERE, "dev_mi.json"), encoding="utf-8"))
    M.setup_chain(dev)
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    rec = {"gps": gps, "auid": auid, "creative": CREATIVE}
    print("GAID:", gps, flush=True)
    t0 = time.time()
    ref = M.click(gps, dev)
    # M.click uses CREATIVE=cline_mintsess; rebuild for our marker
    if not ref:
        print("[F] no referrer")
        sys.exit(1)
    rec["referrer"] = ref
    tb = int(t0) + 30
    ins = F.fmt(int(t0) + 37, 431)
    print("timeline: click=%s begin=%s install=%s"
          % (F.fmt(int(t0), 0).decode(), F.fmt(tb, 0).decode(),
             ins.decode()), flush=True)
    s, r = retry(F.api_session, gps, auid, ins)
    print("SESSION:", s, str(r)[:200], flush=True)
    rec["session"] = [s, str(r)[:600]]
    s2, r2 = retry(F.api_sdk_click, gps, auid, ref, int(t0), tb, ins)
    print("SDK_CLICK:", s2, str(r2)[:250], flush=True)
    rec["sdk_click"] = [s2, str(r2)[:600]]
    ask = 0
    for rr in (r, r2):
        try:
            ask = max(ask, json.loads(rr).get("ask_in", 0) or 0)
        except Exception:
            pass
    if ask:
        w = min(ask / 1000.0, 180.0)
        print("ask_in=%d -> wait %.0fs" % (ask, w), flush=True)
        time.sleep(w)
    ib = "backend" if ask else "sdk"
    ptoken = "e" + uuid.uuid4().hex * 3 + ":APA91b" + uuid.uuid4().hex * 3
    rec["arms"] = []
    for i in (1, 2):
        s3, r3 = retry(F.api_attribution, gps, auid, ptoken, ib)
        try:
            a = json.loads(r3).get("attribution", {})
            v = "%s / %s / eng=%s / inst=%s" % (
                a.get("tracker_token"), a.get("network"),
                a.get("engagement_time"), a.get("installed_at"))
        except Exception:
            v = "HTTP %s %s" % (s3, str(r3)[:200])
        print("ATTR%d: %s" % (i, v), flush=True)
        rec["arms"].append({"http": s3, "verdict": v, "raw": str(r3)[:1500]})
        if i == 1:
            time.sleep(20)
    json.dump(rec, open(OUT, "w"), indent=1)
    print("saved", OUT)


if __name__ == "__main__":
    main()