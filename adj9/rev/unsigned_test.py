# unsigned_test.py — THE "non-adj9 app" CONTROL, the analogy the user keeps
# pointing at: same funnel, same clicked GAID, same real referrer, same device
# transport — the ONLY difference is that the requests carry NO Authorization
# header. On apps without the signature feature this exact flow books
# non-organic; here it tells us whether pentim's app_token is signature-gated.
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_full_chain as F

# ---- the user's real inputs -------------------------------------------------
GPS = "274418fe-880e-4739-9a7f-1ee44c61ab7d"      # the clicked GAID (from link)
REF = ("adjust_reftag=cA1DXYdvcrG5k&utm_source=VKM+Digital+Yeni"
       "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")
DEV = os.path.join(HERE, "dev_mi.json")
OUT = os.path.join(HERE, "unsigned_result.json")

F.NO_SIGN = True          # no Authorization header at all
F.USE_DEVICE = True       # device transport (same as run_funnel via-device)
F.ADD_IDFA = False


def main():
    dev = json.load(open(DEV, encoding="utf-8"))
    import run_funnel as R
    F.DEV, F.UA = R.dev_from_json(dev), R.ua_from_json(dev)
    F.OFF_MINUTES, F.OFF_LABEL = 330, "+0530"
    auid = str(uuid.uuid4())
    now = int(time.time())
    ins = F.fmt(now - 5, 431)
    rec = {"gps": GPS, "auid": auid, "referrer": REF, "signed": False,
           "transport": "device", "steps": []}
    print("UNSIGNED funnel  gps=%s auid=%s" % (GPS, auid), flush=True)
    print("UA:", F.UA, flush=True)

    s, r = F.api_session(GPS, auid, ins)
    print("SESSION : %s %s" % (s, r[:200]), flush=True)
    rec["steps"].append(["session", s, r[:400]])
    time.sleep(3)

    s2, r2 = F.api_sdk_click(GPS, auid, REF, now, now - 1, ins)
    print("SDK_CLICK: %s %s" % (s2, r2[:200]), flush=True)
    rec["steps"].append(["sdk_click", s2, r2[:400]])
    time.sleep(3)

    ptok = "e" + uuid.uuid4().hex * 3 + ":APA91b" + uuid.uuid4().hex * 3
    for i in (1, 2, 3):
        s3, r3 = F.api_attribution(GPS, auid, ptok, "sdk")
        print("ATTR%d   : %s %s" % (i, s3, r3[:400]), flush=True)
        rec["steps"].append(["attr%d" % i, s3, r3[:3000]])
        try:
            a = json.loads(r3)["attribution"]
            rec["verdict"] = "%s / %s / eng=%s" % (
                a.get("tracker_token"), a.get("network"),
                a.get("engagement_time"))
        except Exception:
            pass
        if i == 1:
            time.sleep(15)
    json.dump(rec, open(OUT, "w"), indent=1)
    print("VERDICT:", rec.get("verdict", "-"), flush=True)
    print("saved", OUT)


if __name__ == "__main__":
    main()
