# py_install_test.py - PURE-PYTHON booking test.
#
# Goal: our own Python-crafted, Python-signed /session must create the install
# record for a fresh GAID whose click we fired, and that record must read
# NON-ORGANIC with OUR marker - WITHOUT the app signing anything.
#
# Method:
#   1. fresh GAID (root write + readback verify)              [Python]
#   2. tracker click bound to that GAID, marker creative      [Python]
#   3. crafted signed /session, sent from Python             [Python signature]
#   4. crafted signed /sdk_click (the referrer)              [Python signature]
#   5. launch the app ONLY as a read oracle and read
#      /data/data/com.penti.app/files/AdjustAttribution       [verdict]
#
# Discriminators:
#   * the app's own /session should be refused as "too frequent" => our crafted
#     /session created the record;
#   * 'installed_at' in the verdict should equal our crafted session time;
#   * network/creative must carry OUR marker.
import datetime as dt
import http.client
import json
import os
import subprocess
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
import farm_win as fw

ATTR = "/data/data/com.penti.app/files/AdjustAttribution"
APP = "com.penti.app"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
OUT = os.path.join(HERE, "py_install_result.json")
LOG = {}


def log(k, v):
    LOG[k] = v
    print("[%s] %s" % (k, v), flush=True)


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def post(path, params, blob, ua=UA, timeout=25):
    body = urllib.parse.urlencode(params).encode()
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=timeout)
    conn.putrequest("POST", path, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", F.auth_header(blob))
    conn.putheader("User-Agent", ua)
    conn.putheader("Host", "app.adjust.com")
    conn.putheader("Content-Type", "application/x-www-form-urlencoded")
    conn.putheader("Content-Length", str(len(body)))
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    conn.send(body)
    r = conn.getresponse()
    out = (r.status, r.read().decode("utf-8", "replace"))
    conn.close()
    return out


def session_template():
    """The app's OWN /session parameter set (wh4 golden sign_input, 50 keys),
    so every session-law claim is present."""
    W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
    si = W["sign_inputs"][W["golden_sign_input_idx"]]
    val = {}
    for part in si["order"].split("\x02"):
        if "\x01" in part:
            k, v = part.split("\x01", 1)
            val[k] = v
    return val


def main():
    marker = "cline_pycraft_d"
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    now = time.time()
    second = int(now)

    # ---- 1. fresh GAID ------------------------------------------------------
    got = fw.set_gaid(gps)
    log("gaid", "set %s -> readback %s" % (gps, got))
    if got != gps:
        raise SystemExit("GAID readback mismatch")

    # ---- 2. our click -------------------------------------------------------
    code, ref, hops, url = fw.fire_click(gps, marker, None)
    log("click", "http=%s reftag=%s marker=%s" % (code, (ref or "")[:44], marker))

    # ---- 3. crafted /session (PYTHON signature) ----------------------------
    val = session_template()
    val.update({
        "gps_adid": gps,
        "android_uuid": auid,
        "created_at": plus0530(now, 100),
        "sent_at": plus0530(now, 130),
        "installed_at": plus0530(now - 2, 200),
        "updated_at": plus0530(now - 2, 200),
        "session_count": "1",
        "activity_kind": "session",
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "tracking_enabled": "1",
    })
    st, blob, desc, unpadded = F.make_signature_law(val, "session", second=second)
    log("session/mint", "%s  #10=%dB  blob=%dB  head=%s"
        % (st, unpadded, len(blob), blob[:8].hex()))
    params = dict(val)
    params["ask_in"] = "2000"
    scode, sbody = post("/session", params, blob)
    log("session/send", "POST /session -> %s  %s" % (scode, sbody[:220]))

    # ---- 4. crafted /sdk_click (the referrer) ------------------------------
    if ref:
        click_val = dict(val)
        click_val.update({
            "activity_kind": "click",
            "google_play_instant": "0",
            "referrer": ref,
            "referrer_api": "google",
            "source": "install_referrer",
            "session_length": "0",
            "subsession_count": "1",
            "time_spent": "0",
            "click_time": plus0530(now - 1, 100),
            "click_time_server": plus0530(now - 1, 100),
            "install_begin_time": plus0530(now - 1, 200),
            "install_begin_time_server": plus0530(now - 1, 200),
        })
        try:
            st2, blob2, _, n2 = F.make_signature_law(click_val, "click",
                                                     second=second)
            c2, b2 = post("/sdk_click", click_val, blob2)
            log("sdk_click/send", "POST /sdk_click -> %s  %s" % (c2, b2[:200]))
        except Exception as e:
            log("sdk_click/send", "raised %s: %s"
                % (type(e).__name__, str(e)[:130]))

    # ---- 5. app as READ ORACLE only ----------------------------------------
    time.sleep(3)
    fw.wipe_relaunch()
    verdict, app_ref = {}, ""
    for k in range(6):
        time.sleep(14 if k == 0 else 10)
        verdict, app_ref = fw.read_verdict()
        if verdict:
            break
    log("app_install_referrer", app_ref[:120])
    log("verdict", json.dumps(verdict))
    ok = (bool(verdict) and verdict.get("network") not in (None, "Organic")
          and verdict.get("creative") == marker)
    log("RESULT", "NON-ORGANIC with our marker" if ok else
        ("Organic" if verdict.get("network") == "Organic"
         else "other: %s" % verdict.get("network")))

    LOG.update({"gps": gps, "auid": auid, "marker": marker, "second": second,
                "crafted_installed_at": val["installed_at"],
                "session_status": st, "session_http": scode,
                "session_body": sbody[:400]})
    json.dump(LOG, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT, flush=True)


if __name__ == "__main__":
    main()