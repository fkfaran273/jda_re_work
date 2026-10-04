"""phone_submit.py — mint adj9 signatures locally, submit from the PHONE's IP.

Theory under test: attribution joins on egress IP / Play provenance, which
datacenter submissions can never satisfy. Mint stays in Python (FinEx);
every HTTPS request goes out via adb-shell curl on the moto (106.219.162.119).

Usage:  python phone_submit.py [moto|cph] [gps-adid]
Needs beside it: adj9_full_chain.py + its companions.
"""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as A

DEV = "ZY"
SER = "ZD2228MY3X"
TMP = "C:/Users/Apps/AppData/Local/Temp/opencode"


def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       timeout=timeout)
    return r.stdout.strip()


def onphone(script):
    # run sh script from a file: zero quoting pain across layers.
    # newline='\n' is load-bearing: CRLF breaks device sh parsing.
    with open(os.path.join(TMP, "run.sh"), "w", newline="\n") as f:
        f.write(script)
    sh(ADB + " push %s/run.sh /sdcard/run.sh" % TMP)
    return sh(ADB + " shell sh /sdcard/run.sh")


def phone_curl_tracker(gps):
    url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
           "&creative=penti_generic&gps_adid=" + gps)
    out = onphone("curl -s -D - -o /dev/null --max-time 30"
                  " -A '" + A.UA + "' '" + url + "'\n")
    loc = ""
    for line in out.splitlines():
        if line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
    ref = ""
    if "referrer=" in loc:
        ref = urllib.parse.unquote(loc.split("referrer=", 1)[1])
    print("phone click loc:", loc[:120])
    print("REFERRER:", ref[:120])
    return ref


def auth_line(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())


def curl_post(endpoint, params, blob):
    body = urllib.parse.urlencode(params)
    with open(os.path.join(TMP, "pbody.txt"), "w") as f:
        f.write(body)
    sh(ADB + " push %s/pbody.txt /sdcard/pbody.txt" % TMP)
    script = ("curl -s -w '\\n%{http_code}' --max-time 40 -X POST"
              " -H 'Client-SDK: android5.7.0'"
              " -H 'Authorization: " + auth_line(blob) + "'"
              " -H 'Content-Type: application/x-www-form-urlencoded'"
              " -H 'User-Agent: " + A.UA + "'"
              " --data @/sdcard/pbody.txt"
              " 'https://app.adjust.com/" + endpoint + "'\n")
    out = onphone(script)
    resp, _, code = out.rpartition("\n")  # curl -w appends code LAST
    return code.strip(), resp[:500]


def curl_get(endpoint, params, blob):
    q = urllib.parse.urlencode(params)
    script = ("curl -s -w '\\n%{http_code}' --max-time 40"
              " -H 'Client-SDK: android5.7.0'"
              " -H 'Authorization: " + auth_line(blob) + "'"
              " -H 'User-Agent: " + A.UA + "'"
              " 'https://app.adjust.com/" + endpoint + "?" + q + "'\n")
    out = onphone(script)
    code, _, resp = out.rpartition("\n")
    return code.strip(), resp[:2000]


def main():
    profile = sys.argv[1] if len(sys.argv) > 1 else "moto"
    gps = sys.argv[2] if len(sys.argv) > 2 else str(uuid.uuid4())
    A.DEV = dict(A.MOTO if profile == "moto" else A.DEV)
    if profile == "moto":
        A.UA = A.MOTO_UA
    auid = str(uuid.uuid4())
    import secrets as _s
    ptoken = "e" + _s.token_urlsafe(24) + ":APA91b" + _s.token_urlsafe(96)
    t_track = int(time.time())
    print("profile", profile, "gps", gps, "auid", auid, flush=True)

    ref = phone_curl_tracker(gps)
    assert ref and "adjust_reftag=" in ref, "phone click gave no referrer"
    time.sleep(2)

    sec = int(time.time()) + A.MINT_SKEW
    st, n, b1 = A.make_signature(sec, A.fmt(sec - 1, 928), gps, auid,
                                 A.fmt(sec - 170, 774))
    print("session mint", st, n, flush=True)
    p = dict(A.S1P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": A.fmt(sec - 1, 928).decode(),
              "sent_at": A.fmt(sec - 1, 942).decode(),
              "installed_at": A.fmt(sec - 170, 774).decode(),
              "updated_at": A.fmt(sec - 170, 774).decode()})
    p.update(A.DEV)
    s1, r1 = curl_post("session", p, b1)
    print("SESSION:", s1, r1[:200], flush=True)
    time.sleep(3)

    sec = int(time.time()) + A.MINT_SKEW
    st, n, b2 = A.make_signature(sec, A.fmt(sec - 1, 961), gps, auid,
                                 A.fmt(sec - 170, 774))
    print("click mint", st, n, flush=True)
    p = dict(A.S2P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": A.fmt(sec - 1, 961).decode(),
              "sent_at": A.fmt(sec - 1, 970).decode(),
              "installed_at": A.fmt(sec - 170, 774).decode(),
              "referrer": ref, "source": "install_referrer",
              "referrer_api": "google",
              "click_time": A.fmt(t_track, 0).decode(),
              "click_time_server": A.fmt(t_track + 1, 0).decode(),
              "install_begin_time": A.fmt(t_track + 5, 0).decode(),
              "install_begin_time_server": A.fmt(t_track + 6, 0).decode()})
    p.update(A.DEV)
    s2, r2 = curl_post("sdk_click", p, b2)
    print("CLICK:", s2, r2[:200], flush=True)
    time.sleep(3)

    sec = int(time.time()) + A.MINT_SKEW
    st, n, b3 = A.make_signature(sec, A.fmt(sec - 1, 550), gps, auid)
    print("info mint", st, n, flush=True)
    p = {"gps_adid_attempt": "1", "wait_time": "0.0",
         "app_token": A.APP_TOKEN, "created_at": A.fmt(sec - 1, 550).decode(),
         "wait_total": "0.0", "first_error": "0", "gps_adid": gps,
         "source": "push", "foreground": "1", "android_uuid": auid,
         "sent_at": A.fmt(sec - 1, 665).decode(), "offline_mode_enabled": "0",
         "environment": "production", "needs_response_details": "1",
         "attribution_deeplink": "1", "retry_count": "0", "last_error": "0",
         "gps_adid_src": "service", "push_token": ptoken,
         "enqueue_size": "1", "tracking_enabled": "1"}
    s3, r3 = curl_post("sdk_info", p, b3)
    print("INFO:", s3, r3[:200], flush=True)
    time.sleep(3)

    sec = int(time.time()) + A.MINT_SKEW
    st, n, b4 = A.make_signature(sec, A.fmt(sec - 1, 666), gps, auid)
    print("attr mint", st, n, flush=True)
    p = {"gps_adid_attempt": "1", "api_level": A.DEV["api_level"],
         "app_version": A.DEV["app_version"], "app_token": A.APP_TOKEN,
         "created_at": A.fmt(sec - 1, 666).decode(), "device_type": "phone",
         "gps_adid": gps, "foreground": "1",
         "device_name": A.DEV["device_name"], "needs_response_details": "1",
         "gps_adid_src": "service", "push_token": ptoken,
         "initiated_by": "backend", "os_version": A.DEV["os_version"],
         "android_uuid": auid, "sent_at": A.fmt(sec - 1, 696).decode(),
         "offline_mode_enabled": "0", "environment": "production",
         "attribution_deeplink": "1", "package_name": "com.penti.app",
         "os_name": "android", "ui_mode": "1", "tracking_enabled": "1"}
    s4, r4 = curl_get("attribution", p, b4)
    print("ATTR:", s4, r4[:2000], flush=True)
    try:
        net = json.loads(r4)["attribution"]["network"]
    except Exception:
        net = "?"
    print("VERDICT:", net)
    json.dump({"via": "phone-ip", "gps": gps, "auid": auid,
               "session": [s1, r1[:300]], "click": [s2, r2[:300]],
               "info": [s3, r3[:200]], "attr": [s4, r4[:2000]],
               "verdict": net},
              open(os.path.join(HERE, "phone_submit_result.json"), "w"),
              indent=1)


ADB = "adb -s " + SER
if __name__ == "__main__":
    main()
