# py_book_test.py - CAN OUR PYTHON FIRST SESSION BOOK THE CLICK? Three arms.
#
# The user's claim (2026-09-19): if the server recognises the device by its first
# session / sdk_click + device info, then OUR Python first session / sdk_click,
# carrying the same device info, must be recognised too - "if the device can do it
# then we can also do it".
#
# Previous Python runs always sent BOTH a crafted /session and a crafted
# /sdk_click, so they could never separate "our session cannot book" from "our
# sdk_click broke the join". This script separates them, on fresh GAIDs, reading
# the verdict with our OWN crafted /attribution poll (proven usable on our own
# identities: py_pure.log showed the poll returning OUR record's installed_at).
#
#   Arm S  click -> crafted /session ONLY            (session-only hypothesis)
#   Arm K  click -> crafted /session + crafted /sdk_click   (earlier runs)
#   Arm C  click -> NO crafted call at all           (does a click alone book?)
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
sys.stdout.reconfigure(line_buffering=True)
import adj9_forge as F
import farm_win as fw

HDR_ONLY = {"activity_kind", "adj_signing_id", "adj_verification", "algorithm",
            "client_sdk", "headers_id", "native_version"}
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
OUT = os.path.join(HERE, "py_book_result.json")
LOG = {}


def log(k, v):
    LOG[k] = v
    print("[%s] %s" % (k, v), flush=True)


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def wire(val):
    return {k: v for k, v in val.items() if k not in HDR_ONLY}


def send(method, path, params, blob):
    q = urllib.parse.urlencode(params)
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=25)
    if method == "GET":
        conn.putrequest("GET", path + "?" + q, skip_accept_encoding=1)
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


def sdk_map():
    W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
    si = W["sign_inputs"][W["golden_sign_input_idx"]]
    m = {}
    for part in si["order"].split("\x02"):
        if "\x01" in part:
            k, v = part.split("\x01", 1)
            m[k] = v
    return m


def attr_of(body):
    try:
        return json.loads(body).get("attribution", {})
    except Exception:
        return {}


def arm(label, do_session, do_sdk_click, marker):
    gps, auid = str(uuid.uuid4()), str(uuid.uuid4())
    now = time.time()
    second = int(now)
    rec = {"label": label, "gps": gps, "auid": auid, "marker": marker,
           "session": None, "sdk_click": None, "reads": []}
    log("%s/identity" % label, "gps=%s auid=%s" % (gps, auid))
    code, ref, hops, url = fw.fire_click(gps, marker, None)
    rec["click_http"] = code
    rec["referrer"] = ref
    log("%s/click" % label, "http=%s reftag=%s"
        % (code, (ref or "").split("&")[0]))
    ref_s = (ref or "")
    val = sdk_map()
    val.update({"gps_adid": gps, "android_uuid": auid,
                "created_at": plus0530(now, 100), "sent_at": plus0530(now, 130),
                "installed_at": plus0530(now - 2, 200),
                "updated_at": plus0530(now - 2, 200),
                "session_count": "1", "activity_kind": "session",
                "gps_adid_attempt": "1", "gps_adid_src": "service",
                "tracking_enabled": "1"})
    if do_session:
        st, blob, desc, unp = F.make_signature_law(val, "session", second=second)
        c, b = send("POST", "/session", wire(val), blob)
        rec["session"] = [c, b[:300]]
        log("%s/session" % label, "%s http=%s %s" % (st, c, b[:150]))
    if do_sdk_click and ref_s:
        cv = dict(val)
        cv.update({"activity_kind": "click", "google_play_instant": "0",
                   "referrer": ref_s, "referrer_api": "google",
                   "source": "install_referrer", "session_length": "0",
                   "subsession_count": "1", "time_spent": "0",
                   "click_time": plus0530(now - 1, 100),
                   "click_time_server": plus0530(now - 1, 100),
                   "install_begin_time": plus0530(now - 1, 200),
                   "install_begin_time_server": plus0530(now - 1, 200)})
        try:
            st2, blob2, _, n2 = F.make_signature_law(cv, "click", second=second)
            c2, b2 = send("POST", "/sdk_click", wire(cv), blob2)
            rec["sdk_click"] = [c2, b2[:300]]
            log("%s/sdk_click" % label, "%s http=%s %s" % (st2, c2, b2[:150]))
        except Exception as e:
            log("%s/sdk_click" % label,
                "%s: %s" % (type(e).__name__, str(e)[:100]))
    for attempt in range(3):
        time.sleep(10 if attempt == 0 else 22)
        av = dict(val)
        av.update({"activity_kind": "attribution", "initiated_by": "backend"})
        for k in ("session_count", "installed_at", "updated_at", "hardware_name",
                  "os_build", "initiating_package_name",
                  "store_name_from_system"):
            av.pop(k, None)
        st3, blob3, _, n3 = F.make_signature_law(av, "attribution",
                                                 second=int(time.time()))
        c3, b3 = send("GET", "/attribution", wire(av), blob3)
        a = attr_of(b3)
        rec["reads"].append({"http": c3, "attr": a, "raw": b3[:400]})
        log("%s/read%d" % (label, attempt),
            "http=%s network=%s creative=%s eng=%s inst=%s"
            % (c3, a.get("network"), a.get("creative"),
               a.get("engagement_time"), a.get("installed_at")))
        if a.get("creative") == marker or (a.get("network")
                                           not in (None, "Organic") and
                                           a.get("network")):
            log("%s/RESULT" % label, "*** JOINED / NON-ORGANIC ***")
            break
    json.dump(rec, open(os.path.join(HERE, "py_book_%s.json" % label), "w"),
              indent=1)
    return rec


def main():
    out = []
    out.append(arm("S_session_only", True, False, "cline_book_S"))
    time.sleep(15)
    out.append(arm("K_session_plus_sdkclick", True, True, "cline_book_K"))
    time.sleep(15)
    out.append(arm("C_click_only", False, False, "cline_book_C"))
    json.dump(out, open(OUT, "w"), indent=1)
    print("\n=== SUMMARY ===", flush=True)
    for r in out:
        a = (r["reads"][-1]["attr"] if r["reads"] else {})
        print("  %-22s session=%-4s network=%-10s creative=%-14s eng=%s"
              % (r["label"], "yes" if r["session"] else "no",
                 a.get("network"), a.get("creative"),
                 (a.get("engagement_time") or "")[:19]), flush=True)
    print("\nsaved %s" % OUT, flush=True)


if __name__ == "__main__":
    main()