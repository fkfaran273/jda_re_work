# py_pure_test.py - FULLY DEVICE-FREE pure-Python booking test.
#
# No app, no root, no adb: every request is signed by our own Python maker.
#   1. pick a fresh GAID (uuid4, never seen by the server)
#   2. tracker click bound to that GAID, marker creative        [Python HTTP]
#   3. crafted + signed /session  -> creates the install record  [Python sig]
#   4. crafted + signed /sdk_click (the referrer)                [Python sig]
#   5. crafted + signed /attribution -> READ THE VERDICT         [Python sig]
#
# Reading: if the record was created BY OUR PACKAGES, the server holds our bytes
# for that identity and should return the record's true verdict (non-organic with
# our marker) instead of the silent-Organic fallback. If every /attribution answer
# is 'wy7261z / Organic', the crafted package did not book.
import datetime as dt
import http.client
import json
import os
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
import farm_win as fw

UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
OUT = os.path.join(HERE, "py_pure_result.json")
LOG = {}


def log(k, v):
    LOG[k] = v
    print("[%s] %s" % (k, v), flush=True)


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def send(method, path, params, blob=None, timeout=25):
    q = urllib.parse.urlencode(params)
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=timeout)
    if method == "GET":
        conn.putrequest("GET", path + ("?" + q if q else ""),
                        skip_accept_encoding=1)
        conn.putheader("Content-Length", "0")
    else:
        conn.putrequest("POST", path, skip_accept_encoding=1)
        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
        conn.putheader("Content-Length", str(len(q.encode())))
    conn.putheader("Client-SDK", "android5.7.0")
    if blob:
        conn.putheader("Authorization", F.auth_header(blob))
    conn.putheader("User-Agent", UA)
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    if method == "POST":
        conn.send(q.encode())
    r = conn.getresponse()
    out = (r.status, r.read().decode("utf-8", "replace"))
    conn.close()
    return out


def session_template():
    W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
    si = W["sign_inputs"][W["golden_sign_input_idx"]]
    val = {}
    for part in si["order"].split("\x02"):
        if "\x01" in part:
            k, v = part.split("\x01", 1)
            val[k] = v
    return val


def main():
    marker = "cline_pure_e"
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    now = time.time()
    second = int(now)
    log("identity", "gps=%s auid=%s" % (gps, auid))

    # 2. click (Python)
    ref = None
    try:
        code, ref, hops, url = fw.fire_click(gps, marker, None)
        log("click", "http=%s reftag=%s" % (code, (ref or "")[:44]))
    except Exception as e:
        log("click", "FAILED %s: %s" % (type(e).__name__, str(e)[:120]))

    val = session_template()
    val.update({
        "gps_adid": gps, "android_uuid": auid,
        "created_at": plus0530(now, 100), "sent_at": plus0530(now, 130),
        "installed_at": plus0530(now - 2, 200),
        "updated_at": plus0530(now - 2, 200),
        "session_count": "1", "activity_kind": "session",
        "gps_adid_attempt": "1", "gps_adid_src": "service",
        "tracking_enabled": "1",
    })

    # 3. crafted /session (Python signature)
    st, blob, desc, unp = F.make_signature_law(val, "session", second=second)
    log("session/mint", "%s #10=%dB blob=%dB" % (st, unp, len(blob)))
    p = dict(val)
    p["ask_in"] = "2000"
    c, b = send("POST", "/session", p, blob)
    log("session/send", "%s %s" % (c, b[:200]))

    # 4. crafted /sdk_click (Python signature)
    if ref:
        cv = dict(val)
        cv.update({"activity_kind": "click", "google_play_instant": "0",
                   "referrer": ref, "referrer_api": "google",
                   "source": "install_referrer", "session_length": "0",
                   "subsession_count": "1", "time_spent": "0",
                   "click_time": plus0530(now - 1, 100),
                   "click_time_server": plus0530(now - 1, 100),
                   "install_begin_time": plus0530(now - 1, 200),
                   "install_begin_time_server": plus0530(now - 1, 200)})
        try:
            st2, blob2, _, n2 = F.make_signature_law(cv, "click", second=second)
            c2, b2 = send("POST", "/sdk_click", cv, blob2)
            log("sdk_click/send", "%s %s" % (c2, b2[:200]))
        except Exception as e:
            log("sdk_click/send", "%s: %s" % (type(e).__name__, str(e)[:120]))

    # 5. crafted /attribution READ (Python signature) -------------------------
    booked = False
    for attempt in range(4):
        time.sleep(6 if attempt == 0 else 25)
        av = dict(val)
        av.update({"activity_kind": "attribution", "initiated_by": "backend"})
        for k in ("session_count", "installed_at", "updated_at", "hardware_name",
                  "os_build", "initiating_package_name", "store_name_from_system"):
            av.pop(k, None)
        try:
            st3, blob3, _, n3 = F.make_signature_law(av, "attribution",
                                                     second=int(time.time()))
            c3, b3 = send("GET", "/attribution", av, blob3)
            log("attribution/%d" % attempt, "%s %s" % (c3, b3[:240]))
            if c3 == 200 and '"network":"Organic"' not in b3:
                booked = True
                log("RESULT", "NON-ORGANIC observed from a crafted poll")
                break
        except Exception as e:
            log("attribution/%d" % attempt,
                "%s: %s" % (type(e).__name__, str(e)[:120]))
    if not booked:
        log("RESULT", "no non-organic seen from crafted polls (Organic / fallback)")

    LOG.update({"gps": gps, "auid": auid, "marker": marker})
    json.dump(LOG, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT, flush=True)


if __name__ == "__main__":
    main()