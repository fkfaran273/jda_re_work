# py_wire_test.py - crafted chain with the APP'S EXACT WIRE parametrisation.
#
# Fix under test (wire_diff.log): the app's session wire is 43 params and its
# click wire is 47 - both exactly `map MINUS the 7 header-only fields`. Our crafted
# sends posted the whole map plus `ask_in` (51 / 54), i.e. 8 / 7 params the app
# never sends. The blob still signs the full law map; only the WIRE changes.
import datetime as dt
import http.client
import json
import os
import re
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
import farm_win as fw

HDR_ONLY = {'activity_kind', 'adj_signing_id', 'adj_verification', 'algorithm',
            'client_sdk', 'headers_id', 'native_version'}
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
OUT = os.path.join(HERE, "py_wire_result.json")
LOG = {}


def log(k, v):
    LOG[k] = v
    print("[%s] %s" % (k, v), flush=True)


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def wire(val):
    """the app's wire set: the map minus the 7 header-only fields"""
    return {k: v for k, v in val.items() if k not in HDR_ONLY}


def send(method, path, params, blob, timeout=25):
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


def session_map():
    W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
    si = W["sign_inputs"][W["golden_sign_input_idx"]]
    m = {}
    for part in si["order"].split("\x02"):
        if "\x01" in part:
            k, v = part.split("\x01", 1)
            m[k] = v
    return m


def click_map():
    DEV = os.path.join(os.path.dirname(HERE), "device")
    G6 = json.load(open(os.path.join(DEV, "gold6.json"), encoding="utf-8"))
    n = max(len(v) for v in G6.values())
    for i in range(n):
        v = G6["sign_input"][i]
        txt = (" ".join(str(x) for x in v) if isinstance(v, (list, tuple))
               else str(v))
        if "map_toString=" in txt and "referrer" in txt:
            body = txt.split("map_toString=", 1)[1].strip()
            return dict(re.findall(
                r"([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*?)(?=, |$|,)",
                body + ","))
    return {}


def main():
    marker = "cline_wire_f"
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    now = time.time()
    second = int(now)
    log("identity", "gps=%s auid=%s marker=%s" % (gps, auid, marker))

    got = fw.set_gaid(gps)
    log("gaid", "readback %s %s" % (got, "OK" if got == gps else "MISMATCH"))
    if got != gps:
        raise SystemExit("GAID readback mismatch")

    try:
        code, ref, hops, url = fw.fire_click(gps, marker, None)
        log("click", "http=%s reftag=%s" % (code, (ref or "")[:46]))
    except Exception as e:
        ref = None
        log("click", "FAILED %s: %s" % (type(e).__name__, str(e)[:110]))

    # ---- crafted /session: blob = full law map, wire = map - 7 --------------
    val = session_map()
    val.update({
        "gps_adid": gps, "android_uuid": auid,
        "created_at": plus0530(now, 100), "sent_at": plus0530(now, 130),
        "installed_at": plus0530(now - 2, 200),
        "updated_at": plus0530(now - 2, 200),
        "session_count": "1", "activity_kind": "session",
        "gps_adid_attempt": "1", "gps_adid_src": "service",
        "tracking_enabled": "1",
    })
    st, blob, desc, unp = F.make_signature_law(val, "session", second=second)
    wp = wire(val)
    log("session", "%s #10=%dB blob=%dB | signing %d keys, WIRE %d params"
        % (st, unp, len(blob), len(val), len(wp)))
    c, b = send("POST", "/session", wp, blob)
    log("session/send", "%s %s" % (c, b[:200]))

    # ---- crafted /sdk_click: blob = click law map, wire = map - 7 -----------
    cm = click_map()
    if cm and ref:
        cm.update({
            "gps_adid": gps, "android_uuid": auid,
            "created_at": plus0530(now, 100), "sent_at": plus0530(now, 130),
            "installed_at": plus0530(now - 2, 200),
            "updated_at": plus0530(now - 2, 200),
            "session_count": "1", "activity_kind": "click",
            "gps_adid_attempt": "1", "gps_adid_src": "service",
            "tracking_enabled": "1", "google_play_instant": "0",
            "referrer": ref, "referrer_api": "google",
            "source": "install_referrer", "session_length": "0",
            "subsession_count": "1", "time_spent": "0",
            "click_time": plus0530(now - 6, 100),
            "click_time_server": plus0530(now - 6, 100),
            "install_begin_time": plus0530(now - 1, 200),
            "install_begin_time_server": plus0530(now - 1, 200),
        })
        try:
            st2, blob2, _, n2 = F.make_signature_law(cm, "click", second=second)
            wp2 = wire(cm)
            log("sdk_click", "%s signing %d keys, WIRE %d params"
                % (st2, len(cm), len(wp2)))
            c2, b2 = send("POST", "/sdk_click", wp2, blob2)
            log("sdk_click/send", "%s %s" % (c2, b2[:200]))
        except Exception as e:
            log("sdk_click/send", "%s: %s" % (type(e).__name__, str(e)[:130]))

    # ---- crafted /attribution reads ----------------------------------------
    for attempt in range(4):
        time.sleep(8 if attempt == 0 else 25)
        av = dict(val)
        av.update({"activity_kind": "attribution", "initiated_by": "backend"})
        for k in ("session_count", "installed_at", "updated_at", "hardware_name",
                  "os_build", "initiating_package_name",
                  "store_name_from_system"):
            av.pop(k, None)
        try:
            st3, blob3, _, n3 = F.make_signature_law(av, "attribution",
                                                     second=int(time.time()))
            c3, b3 = send("GET", "/attribution", wire(av), blob3)
            log("attribution/%d" % attempt, "%s %s" % (c3, b3[:200]))
        except Exception as e:
            log("attribution/%d" % attempt,
                "%s: %s" % (type(e).__name__, str(e)[:110]))

    log("crafted_installed_at", val["installed_at"])
    LOG.update({"gps": gps, "auid": auid, "marker": marker})
    json.dump(LOG, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT, flush=True)
    print("NOW run: python py_verdict.py %s %s" % (gps, marker), flush=True)


if __name__ == "__main__":
    main()