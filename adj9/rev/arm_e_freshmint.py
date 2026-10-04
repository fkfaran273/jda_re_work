"""arm_e_freshmint.py — ARM E: ARM C verbatim + FRESH TIMESTAMP LAW.

The one variable never held constant in ANY Python arm: the Python FinEx mint
takes ~56 s CPU, and every arm stamped created_at/sent_at/header-second at
MINT START (sec = now-2), so all three signed calls reached app.adjust.com
with declared times ~58-120 s in the past.  The winning device (M4 SAZ,
byte-verified in siggate2_offline.py) shows created_at ~ sign_second - 1..2
and receipt ~ sign_second, i.e. Adjust always receives a FRESH signature
(<= ~3 s old).  If the server gates attribution on signature freshness
(anti-replay / anti-precompute), every Python arm fails while every device
win passes - with zero other differences needed.

This arm reproduces ARM C byte-for-byte (same profile, 43/47/22 params,
F.py region, real 217.431 s CTIT, Play-referrer placeholder, same click
firing) with ONE change: each signed call is minted for a FUTURE second T
and fired at T, so Adjust receives header-second == receipt second and
created_at == receipt - ~1 s, exactly the device envelope.

Run:  python -u arm_e_freshmint.py            (live; ~8 min; logs everything)
"""
import json
import multiprocessing as mp
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mint_pipeline as M
import run_funnel as RF
import adj9_full_chain as FC
from header_gen import make_header

PROFILE = json.load(open(os.path.join(HERE, "moto_g42_profile.json")))
CTIT_INSTALL = 217.431
CTIT_BEGIN = 210.0
OUT = os.path.join(HERE, "arm_e_result.json")

FC.DEV = dict(PROFILE["DEV"])
FC.UA = PROFILE["UA"]
FC.OFF_MINUTES, FC.OFF_LABEL = PROFILE["OFF_MINUTES"], PROFILE["OFF_LABEL"]
FC.ADD_IDFA = PROFILE["ADD_IDFA"]
FC.USE_PROXY = False
FC.USE_DEVICE = False

PLAY_REFERRER = "utm_source=(not%20set)&utm_medium=(not%20set)"
LOG = []


def log(entry):
    entry["t"] = time.time()
    LOG.append(entry)
    print("[log] %s -> %s" % (entry.get("what"), str(entry.get("status"))),
          flush=True)


def session_params(gps, auid, ins, T):
    """Golden S1P (43 keys), created_at/sent_at stamped at sign-second - 1."""
    p = dict(FC.S1P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": FC.fmt(T - 1, 753).decode(),
              "sent_at": FC.fmt(T - 1, 808).decode(),
              "installed_at": ins, "updated_at": ins})
    p.update(FC.DEV)
    for k in ("no_sim", "mcc", "mnc", "install_version"):
        p.pop(k, None)
    return p


def click_params(gps, auid, ref, t_track, tb, ins, T):
    """Golden S2P (47 keys), ARM C's exact click body, fresh stamps."""
    p = dict(FC.S2P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": FC.fmt(T - 1, 846).decode(),
              "sent_at": FC.fmt(T - 1, 871).decode(),
              "installed_at": ins, "referrer": ref,
              "source": "install_referrer", "referrer_api": "google",
              "click_time": FC.fmt(int(t_track), 0).decode(),
              "click_time_server": FC.fmt(int(t_track) - 2, 0).decode(),
              "install_begin_time": FC.fmt(int(tb), 0).decode(),
              "install_begin_time_server": FC.fmt(int(tb) - 2, 0).decode(),
              "updated_at": ins})
    p.update(FC.DEV)
    for k in ("no_sim", "mcc", "mnc"):
        p.pop(k, None)
    return p


def attr_params(gps, auid, T, initiated_by="backend"):
    """The device's exact 22-param GET set, fresh stamps."""
    return {"initiated_by": initiated_by, "gps_adid_attempt": "1",
            "api_level": FC.DEV["api_level"],
            "app_version": FC.DEV["app_version"], "app_token": FC.APP_TOKEN,
            "os_version": FC.DEV["os_version"],
            "created_at": FC.fmt(T - 1, 322).decode(), "device_type": "phone",
            "gps_adid": gps, "foreground": "1", "android_uuid": auid,
            "sent_at": FC.fmt(T - 1, 358).decode(), "offline_mode_enabled": "0",
            "device_name": FC.DEV["device_name"], "environment": "production",
            "needs_response_details": "1", "attribution_deeplink": "1",
            "package_name": "com.penti.app", "os_name": "android",
            "ui_mode": "1", "gps_adid_src": "service", "tracking_enabled": "1"}


# ------------------------------------------------------------------ mints ---
def mint_worker(job, q):
    """Mint one blob for an explicit FUTURE sign-second. Runs in a subprocess."""
    val = M.claims_from_wire(job["params"], job["kind"])
    V = M.make_V(job["T"])
    blob, info = M.mint_blob_ex(val, job["T"], V=V, kind=job["kind"])
    ok = blob[:16] == make_header(job["T"])
    q.put({"name": job["name"], "blob": blob.hex(), "status": info["status"],
           "steps": info["steps"], "header_law_ok": ok})


def mint_all(jobs):
    """Mint all jobs in parallel subprocesses; return {name: result}."""
    q = mp.Queue()
    procs = [mp.Process(target=mint_worker, args=(j, q)) for j in jobs]
    t0 = time.time()
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    out = {}
    for _ in jobs:
        r = q.get()
        assert r["header_law_ok"] and r["status"] == "exit-clean", r
        r["blob"] = bytes.fromhex(r["blob"])
        out[r["name"]] = r
        log({"what": "mint %s" % r["name"], "status": r["status"],
             "steps": r["steps"]})
    print("[arm-e] %d mints done in %.0fs (parallel)" % (len(jobs),
                                                         time.time() - t0),
          flush=True)
    return out


def fire_at(T, url, params, blob, method, what):
    """Send exactly at second T (the blob's sign-second)."""
    while True:
        dt = T - time.time()
        if dt <= 0.05:
            break
        time.sleep(min(dt - 0.02, 0.5))
    t0 = time.time()
    if method == "POST":
        st, body = FC.send(url, params, blob)
    else:
        st, body = FC.send(url, params, blob, "GET")
    log({"what": what, "status": st, "sign_second": T,
         "fired_at": t0, "lag": time.time() - t0, "resp": str(body)[:500]})
    return st, body


def main():
    res = {"arm": "E (ARM C + fresh-timestamp law)", "profile": "moto g42"}
    gps, link = M._fresh_gps_link(RF.LINK)
    auid = str(uuid.uuid4())
    res["gps"], res["auid"] = gps, auid
    print("[arm-e] fresh gps=%s auid=%s" % (gps, auid), flush=True)

    CLICK_DEV = {"locale": {"language": "tr", "country": "TR"},
                 "User-Agent": FC.UA,
                 "os_version": PROFILE["DEV"]["os_version"],
                 "model": PROFILE["DEV"]["device_name"],
                 "build": PROFILE["DEV"]["os_build"], "mcc": "", "mnc": ""}

    # STEP 1 — tracker click, byte-identical to ARM C's.
    t_click = time.time()
    ref, hop = RF.click_tracker(link, gps, FC.UA, CLICK_DEV)
    print("[arm-e] click fired, ref=%s" % (ref or "")[:120], flush=True)
    assert ref and "adjust_reftag=" in ref, "tracker gave no referrer"
    res["referrer"] = ref
    res["reftag"] = ref.split("adjust_reftag=", 1)[1].split("&")[0]
    log({"what": "tracker click", "status": "302", "reftag": res["reftag"],
         "hop": str(hop)[:160]})

    ins = FC.fmt(int(t_click) + int(CTIT_INSTALL), 431).decode()
    tb = t_click + CTIT_BEGIN

    # Timeline: device first-open lag (installed_at ~55 s before the session,
    # as in the M4 win), then session/click/attr ~3-8 s apart, all FRESH.
    T_sess = int(t_click) + int(CTIT_INSTALL) + 55 + 30
    T_click = T_sess + 3
    T_attr1 = T_click + 8
    T_attr2 = T_attr1 + 45
    print("[arm-e] plan: session@%d click@%d attr@%d/%d (now %d)"
          % (T_sess, T_click, T_attr1, T_attr2, int(time.time())), flush=True)

    # STEP 2 — build all param sets NOW (stamps bound to their send seconds),
    # then mint everything in parallel during the CTIT wait.
    jobs = [
        {"name": "session", "kind": "session", "T": T_sess,
         "params": session_params(gps, auid, ins, T_sess)},
        {"name": "sdk_click", "kind": "click", "T": T_click,
         "params": click_params(gps, auid, PLAY_REFERRER, t_click, tb, ins,
                                T_click)},
        {"name": "attr1", "kind": "attribution", "T": T_attr1,
         "params": attr_params(gps, auid, T_attr1)},
        {"name": "attr2", "kind": "attribution", "T": T_attr2,
         "params": attr_params(gps, auid, T_attr2)},
    ]
    res["n_session_params"] = len(jobs[0]["params"])
    res["n_click_params"] = len(jobs[1]["params"])
    res["n_attr_params"] = len(jobs[2]["params"])
    blobs = mint_all(jobs)
    json.dump(res, open(OUT, "w"), indent=1)

    # STEP 3 — fire each call at its sign-second.
    st, body = fire_at(T_sess, "https://app.adjust.com/session",
                       jobs[0]["params"], blobs["session"]["blob"], "POST",
                       "POST /session")
    res["session"] = [st, str(body)[:400]]
    json.dump(res, open(OUT, "w"), indent=1)

    st, body = fire_at(T_click, "https://app.adjust.com/sdk_click",
                       jobs[1]["params"], blobs["sdk_click"]["blob"], "POST",
                       "POST /sdk_click")
    res["sdk_click"] = [st, str(body)[:600]]
    json.dump(res, open(OUT, "w"), indent=1)

    st, body = fire_at(T_attr1, "https://app.adjust.com/attribution",
                       jobs[2]["params"], blobs["attr1"]["blob"], "GET",
                       "GET /attribution #1")
    res["attr1"] = [st, str(body)[:1200]]

    st, body = fire_at(T_attr2, "https://app.adjust.com/attribution",
                       jobs[3]["params"], blobs["attr2"]["blob"], "GET",
                       "GET /attribution #2")
    res["attr2"] = [st, str(body)[:1200]]

    for key in ("attr1", "attr2"):
        try:
            a = json.loads(res[key][1]).get("attribution", {})
        except Exception:
            a = {}
        res.setdefault("verdicts", []).append(a)
    res["request_log"] = LOG
    json.dump(res, open(OUT, "w"), indent=1)

    print("\n==== ARM E VERDICTS ====")
    for v in res["verdicts"]:
        print("  token=%s network=%s eng=%s inst=%s"
              % (v.get("tracker_token"), v.get("network"),
                 v.get("engagement_time"), v.get("installed_at")))
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    mp.freeze_support()
    main()
