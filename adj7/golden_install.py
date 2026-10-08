"""golden_install.py -- the device-template installer.

Takes the BOOKED device rows (payruki_again_same_wifi.saz sids 41/42/43/44:
session/sdk_click/attribution/event that booked VL-Alliance) as byte-exact
templates and replaces ONLY the dynamic values:

  * timestamps: every golden offset from click_time_server preserved to the
    millisecond (installed=+41.201, session created=+212.979 sent=+213.355,
    click req=+214.288/+214.574, attribution=+216.764/+216.777,
    event=+217.756/+217.776), anchored at the NEW click's server second
  * gaid / android_uuid: fresh uuid4
  * referrer: the NEW click's reftag (its utm_* string, device-shaped)
  * partner_params: same JSON shape, fresh uuid

Laws applied (verified on the golden rows):
  * signing second = the request's SENT second (row 41: created 32.979 /
    sent 33.355 -> header == make_header(sent second))
  * each request fires when the wall clock reaches its stamped sent_at

    python golden_install.py            # live: click -> 213s -> all four
    python golden_install.py --dry-run  # offline build + self-verify only
"""
import calendar
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7_pure as sg
from curl_cffi import requests as cr

SAZ = r"C:\Users\Apps\Downloads\payruki_again_same_wifi.saz"
CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
CS = "android5.6.0"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
LINK = ("http://clicks.mobpine.com/api/track/v1/click"
        "?aff_id=3&offer_id=23483498&sub3={gaid}")
DRY = "--dry-run" in sys.argv
IST = timezone(timedelta(hours=5, minutes=30))


def fields_of(sid, kind):
    z = zipfile.ZipFile(SAZ)
    c = z.read("raw/%s_c.txt" % sid)
    line1 = c.split(b"\r\n", 1)[0].decode("latin1")
    if kind == "attribution":
        q = line1.split(" ", 1)[1].rsplit(" HTTP", 1)[0].split("?", 1)[1]
        return dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
    head, _, body = c.partition(b"\r\n\r\n")
    cl = int(re.search(rb"Content-Length: (\d+)", head).group(1))
    return dict(urllib.parse.parse_qsl(body[:cl].decode("latin1"),
                                       keep_blank_values=True))


def ep(ts):
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z",
                 ts)
    Y, Mo, Dd, h, mi, s, ms = m.groups()
    return calendar.timegm((int(Y), int(Mo), int(Dd), int(h), int(mi),
                            int(s))) + int(ms) / 1000.0


def stamp(epoch_float):
    dt = datetime.fromtimestamp(epoch_float, IST)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0530" % (
        dt.microsecond // 1000)


def wait_until(t):
    d = t - time.time()
    if d > 0:
        time.sleep(d)


def main():
    tmpl = {"session": fields_of("41", "session"),
            "click": fields_of("42", "sdk_click"),
            "attribution": fields_of("43", "attribution"),
            "event": fields_of("44", "event")}
    T0 = ep(tmpl["click"]["click_time_server"])

    # --preclick mode: the click was already fired (browser_click.py saved
    # preclick.env); read it, compute the stamps, send immediately
    pre = os.environ.get("FUNNEL_PRECLICK")
    if pre:
        env = {}
        for line in open(pre, encoding="utf-8"):
            k, _, v = line.strip().partition("=")
            if k:
                env[k] = v
        gaid = env["gaid"]; referrer = env["referrer"]; T = int(env["click_server_sec"])
        print("preclick: gaid=%s ref=%s T=%d" % (gaid, referrer[:40], T))
    else:
        # 1. the click (real Chrome through the proven helper)
        gaid = str(uuid.uuid4())
        out = subprocess.run(
            ["python", "-u", os.path.join(HERE, "browser_click.py"),
             LINK.replace("{gaid}", gaid)],
            capture_output=True, text=True, timeout=120).stdout
        rm = re.search(r"REFTAG=(\S+)", out)
        cm = re.search(r"CLICK_SEC=(\d+)", out)
        if not (rm and cm) and not DRY:
            print("no reftag:", out[:200])
            return 1
        referrer = rm.group(1) if rm else tmpl["click"]["referrer"]
        T = int(cm.group(1)) if cm else int(time.time())
    print("click   %s" % referrer[:60])
    print("gaid    %s  | server sec %d" % (gaid, T))

    au = str(uuid.uuid4())
    pp = '{"payrupik_c_id":"%s"}' % str(uuid.uuid4())
    shift = T - T0      # anchor: preserve every golden offset
    # preclick mode: the CTIT already elapsed in wall time; send NOW

    def dyn(fields, kind):
        f = dict(fields)
        f["gps_adid"] = gaid
        if "android_uuid" in f:
            f["android_uuid"] = au
        if "partner_params" in f:
            f["partner_params"] = pp
        if "referrer" in f:
            f["referrer"] = referrer
        for k in ("created_at", "sent_at", "installed_at", "updated_at",
                  "click_time", "click_time_server", "install_begin_time",
                  "install_begin_time_server"):
            if k in f:
                f[k] = stamp(ep(fields[k]) + shift)
        return f

    requests_plan = []
    for kind in ("session", "click", "attribution", "event"):
        f = dyn(tmpl[kind], kind)
        sent_epoch = ep(f["sent_at"])
        requests_plan.append((kind, f, sent_epoch))

    # offline self-verify: field counts + the sent-second signing law
    for kind, f, se in requests_plan:
        auth = sg.sign_request(f, kind, second=int(se), cert_sha1=CERT,
                               client_sdk=CS, include_block2=True,
                               headers_id="8", native_version="3.62.0")
        blob = bytes.fromhex(
            re.search(r'signature="([A-F0-9]{608})"', auth).group(1))
        assert sg.make_header(int(se)) == blob[:16], kind
        assert sg.verify_tag(blob), kind
        print("verify %-11s fields=%2d sent=%s tag+header OK"
              % (kind, len(f), f["sent_at"]))
    if DRY:
        print("dry run -- not sending")
        return 0

    if pre:
        pass          # stamps computed below; no wait needed
    # crash-safe: persist the run identity BEFORE any send
    run_state = {"gaid": gaid, "android_uuid": au, "referrer": referrer,
                 "click_sec": T, "partner_params": pp}
    with open(os.path.join(HERE, "golden_run.json"), "w") as _f:
        json.dump(run_state, _f, indent=1)

    session = cr.Session(impersonate="chrome131_android")
    adid = ""
    for kind, f, se in requests_plan:
        wait_until(se)                       # wall clock == stamped sent_at
        auth = sg.sign_request(f, kind, second=int(se), cert_sha1=CERT,
                               client_sdk=CS, include_block2=True,
                               headers_id="8", native_version="3.62.0")
        print("firing %-11s at %s" % (kind, time.strftime("%H:%M:%S")),
              flush=True)
        if kind == "attribution":
            url = ("https://app.adjust.com/attribution?"
                   + urllib.parse.urlencode(f))
            r = session.get(url, headers={
                "Client-SDK": CS, "Authorization": auth, "User-Agent": UA,
                "Accept-Encoding": "gzip"}, timeout=40)
        else:
            r = session.post("https://app.adjust.com/" +
                             ("sdk_click" if kind == "click" else kind),
                             data=urllib.parse.urlencode(f).encode(), headers={
                                 "Client-SDK": CS, "Authorization": auth,
                                 "User-Agent": UA,
                                 "Content-Type":
                                     "application/x-www-form-urlencoded",
                                 "Accept-Encoding": "gzip"}, timeout=40)
        print("%-11s -> HTTP %d  %s" % (kind, r.status_code, r.text[:130]),
              flush=True)
        try:
            j = r.json()
            adid = j.get("adid", adid)
        except ValueError:
            pass

    # the double-ask + short polls (the device's ask#2 earned the verdict)
    verdict = {}
    for delay in (1.4, 3, 8, 20, 30):
        time.sleep(delay)
        f = dyn(tmpl["attribution"], "attribution")
        now = time.time()
        f["created_at"] = stamp(now)
        f["sent_at"] = stamp(now + 0.013)
        auth = sg.sign_request(f, "attribution", second=int(now + 0.013),
                               cert_sha1=CERT, client_sdk=CS,
                               include_block2=True, headers_id="8",
                               native_version="3.62.0")
        url = ("https://app.adjust.com/attribution?"
               + urllib.parse.urlencode(f))
        r = session.get(url, headers={
            "Client-SDK": CS, "Authorization": auth, "User-Agent": UA,
            "Accept-Encoding": "gzip"}, timeout=40)
        try:
            verdict = r.json().get("attribution") or verdict
        except ValueError:
            pass
        print("poll +%-4s -> %s / %s" % (delay, verdict.get("network"),
                                         verdict.get("tracker_token")))
        if verdict.get("network") and verdict["network"] != "Organic":
            break
    print()
    if verdict.get("network", "Organic") != "Organic":
        print("*** NON-ORGANIC ***  adid=%s" % adid)
        for k in ("network", "tracker_token", "tracker_name", "campaign",
                  "adgroup", "engagement_time"):
            print("  %-16s %s" % (k, verdict.get(k)))
        return 0
    print("*** Organic ***  adid=%s" % adid)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
