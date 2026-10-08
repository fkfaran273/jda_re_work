"""replay_golden_fresh.py -- golden-replay funnel (copies only, originals untouched).

Takes the paid golden capture (payruki_again rows 41-44, booked 248wk8ym)
and re-fires it field-for-field, changing ONLY dynamic values:
  gps_adid (fresh GAID), android_uuid, partner payrupik_c_id, referrer
  (fresh live reftag), and timestamps (shifted to now, golden deltas kept).

Golden timing anchors (+0530), offsets from click_time T0:
  click_time_server -1.000 | install_begin +19.000 (+server twin) |
  installed/updated +40.201 | session created +191.979 sent +192.355 |
  click created +193.288 sent +193.574 | attr created +195.764 sent +195.777 |
  event created +196.756 sent +196.776. ms fractions preserved exactly.

  python replay_golden_fresh.py --dry-run   # build + sign, send nothing
  python replay_golden_fresh.py             # live fire
"""
import gzip
import http.client
import json
import os
import re
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7_pure as sg
import run_fix1 as R

RAW = r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payruki_again\raw"
DRY_RUN = "--dry-run" in sys.argv

CAMPAIGN = dict(R.CAMPAIGN)
CLIENT_SDK = CAMPAIGN["client_sdk"]
APP_UA = R.APP_UA

OFF = 5 * 3600 + 30 * 60  # +0530 seconds


def stamp(epoch_float, ms):
    dt = datetime.fromtimestamp(int(epoch_float) + OFF, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms) + "Z+0530"


def load_row(idx):
    text = open(os.path.join(RAW, "%02d_c.txt" % idx),
                 encoding="utf-8").read()
    sep = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
    head, _, rest = text.partition(sep)
    lines = head.replace("\r\n", "\n").split("\n")
    method, target, _ = lines[0].split(" ", 2)
    headers, body = {}, ""
    for ln in lines[1:]:
        if ": " in ln:
            k, v = ln.split(": ", 1)
            headers[k] = v
    body = rest.replace("\r\n", "\n").strip()
    return method, target, headers, body


def ordered_fields(body_or_query):
    return urllib.parse.parse_qsl(body_or_query, keep_blank_values=True)


def main():
    gaid = os.environ.get("FUNNEL_GAID") or str(uuid.uuid4())
    auuid = str(uuid.uuid4())
    partner = str(uuid.uuid4())
    started = time.time()
    print("campaign  in.hanafintech / smxi7gqwu39c (golden-replay)")
    print("gaid      %s" % gaid)

    # 1. live click -> fresh reftag (or override for dry-run audit)
    referrer = os.environ.get("FUNNEL_REFTAG", "")
    if not DRY_RUN and not referrer:
        referrer = R.open_click_link(gaid)
        if not referrer:
            print("no reftag -- aborting")
            return 1
    if not referrer:
        referrer = ("adjust_reftag=DRYRUNREFTAG12&utm_source=VL-Alliance"
                    "&utm_campaign=HM2&utm_content=HM2_1722_")
    print("reftag    %s" % referrer[:80])
    click_second = int(time.time()) - 1
    T0 = click_second + 13  # golden engagement->click_time +13s

    def TS(off_sec, ms):
        return stamp(T0 + off_sec, ms)

    # golden (session, click, attr, event) field orders + static values
    m41, t41, h41, b41 = load_row(41)
    m42, t42, h42, b42 = load_row(42)
    m43, t43, h43, b43 = load_row(43)
    m44, t44, h44, b44 = load_row(44)
    sess = ordered_fields(b41)
    click = ordered_fields(b42)
    attr = ordered_fields(urllib.parse.urlsplit(t43).query)
    event = ordered_fields(b44)

    dyn_time = {
        "click_time": TS(0, 0), "click_time_server": TS(-1, 0),
        "install_begin_time": TS(19, 0), "install_begin_time_server": TS(19, 0),
        "installed_at": TS(40.201, 201), "updated_at": TS(40.201, 201),
    }
    sched = {  # name -> (created_off, created_ms, sent_off, sent_ms, kind)
        # offsets from click_time T0; session straddles a second boundary,
        # so the signing second is the SENT second (golden row41 proof)
        "session": (211.979, 979, 212.355, 355, "session"),
        "click": (213.288, 288, 213.574, 574, "click"),
        "attr": (215.764, 764, 215.777, 777, "attribution"),
        "event": (216.756, 756, 216.776, 776, "event"),
    }

    def build(pairs, which, gaid, auuid, partner, referrer):
        coff, cms, soff, sms, kind = sched[which]
        out = []
        for k, v in pairs:
            if k == "gps_adid":
                v = gaid
            elif k == "android_uuid":
                v = auuid
            elif k == "partner_params":
                v = json.dumps({"payrupik_c_id": partner},
                               separators=(",", ":"))
            elif k == "callback_params":
                v = json.dumps({"google_adid": gaid}, separators=(",", ":"))
            elif k == "referrer":
                v = referrer
            elif k in dyn_time:
                v = dyn_time[k]
            elif k == "created_at":
                v = TS(coff, cms)
            elif k == "sent_at":
                v = TS(soff, sms)
            out.append((k, v))
        # signing second = the SENT second (device signs at send; golden
        # row 41 straddles 32.979/33.355 and its header == sent second)
        return out, kind, int(T0 + soff)

    jobs = [("session", sess, "POST", "/session"),
            ("click", click, "POST", "/sdk_click"),
            ("attr", attr, "GET", "/attribution"),
            ("event", event, "POST", "/event")]
    built = []
    for which, pairs, method, path in jobs:
        fields, kind, sec = build(pairs, which, gaid, auuid, partner,
                                  referrer)
        auth = sg.sign_request(dict(fields), kind, second=sec,
                               cert_sha1=CAMPAIGN["cert_sha1"],
                               client_sdk=CLIENT_SDK, include_block2=True,
                               headers_id="8", native_version="3.62.0")
        blob = bytes.fromhex(
            re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1))
        import hashlib
        import hmac as hm
        tag_ok = hm.new(sg.DK37, blob[16:272],
                        hashlib.sha256).digest() == blob[272:304]
        print("built   /%-10s %3d fields sec=%d tag_ok=%s created=%s" %
              (path.strip("/"), len(fields), sec, tag_ok,
               dict(fields)["created_at"]))
        built.append((which, method, path, fields, auth, sec))

    if DRY_RUN:
        json.dump({"gaid": gaid, "android_uuid": auuid,
                   "reftag": referrer, "click_second": click_second,
                   "fields": {w: f for w, _, _, f, _, _ in built}},
                  open(os.path.join(HERE, "golden_replay_dry.json"), "w"),
                  indent=1)
        print("dry-run written, sending nothing")
        return 0

    def call(method, path, fields, auth):
        if method == "POST":
            body = urllib.parse.urlencode(fields).encode()
            target = path
        else:
            body = None
            target = path + "?" + urllib.parse.urlencode(
                fields, quote_via=urllib.parse.quote)
        c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
        try:
            c.putrequest(method, target, skip_host=1,
                         skip_accept_encoding=1)
            c.putheader("Client-SDK", CLIENT_SDK)
            c.putheader("Authorization", auth)
            if body is not None:
                c.putheader("Content-Type",
                            "application/x-www-form-urlencoded")
            c.putheader("User-Agent", APP_UA)
            c.putheader("Host", "app.adjust.com")
            c.putheader("Connection", "Keep-Alive")
            c.putheader("Accept-Encoding", "gzip")
            if body is not None:
                c.putheader("Content-Length", str(len(body)))
            c.endheaders(body)
            r = c.getresponse()
            raw = r.read()
            if raw[:2] == bytes((0x1F, 0x8B)):
                raw = gzip.decompress(raw)
            return r.status, raw.decode("utf-8", "replace")
        finally:
            c.close()

    # fire on golden schedule (session wall = sent time T0+212.355)
    for which, method, path, fields, auth, sec in built:
        if which == "event":
            continue  # event goes after attribution verdict
        want = T0 + sched[which][2]  # sent offset: never stamp sent in future
        wait = want - time.time()
        if wait > 0:
            time.sleep(wait)
        st, body = call(method, path, fields, auth)
        print("%-8s -> HTTP %d  %s  [t=+%.0fs]" %
              (which, st, body[:130], time.time() - started))
        if which == "session":
            try:
                print("   ask_in:", json.loads(body).get("ask_in"))
            except Exception:
                pass
        if which == "attr":
            verdict = (json.loads(body).get("attribution") or {})
            print("   VERDICT: %s / %s" % (verdict.get("network"),
                                           verdict.get("tracker_token")))

    # fallback poll + event (methodology parity, not golden)
    verdict = {}
    try:
        verdict = json.loads(body).get("attribution") or {}
    except Exception:
        pass
    if verdict.get("network", "Organic") == "Organic":
        time.sleep(30)
        sec = int(time.time())
        f2 = [ (k, (stamp(sec, 539) if k == "created_at"
                    else stamp(sec, 569) if k == "sent_at" else v))
               for k, v in built[2][3] ]
        a2 = sg.sign_request(dict(f2), "attribution", second=sec,
                             cert_sha1=CAMPAIGN["cert_sha1"],
                             client_sdk=CLIENT_SDK, include_block2=True,
                             headers_id="8", native_version="3.62.0")
        st, body = call("GET", "/attribution", f2, a2)
        try:
            verdict = json.loads(body).get("attribution") or verdict
        except Exception:
            pass
        print("poll +30s  -> %s / %s" % (verdict.get("network"),
                                         verdict.get("tracker_token")))
    time.sleep(2.0)
    which, method, path, fields, auth, sec = built[3]
    st, body = call(method, path, fields, auth)
    print("event    -> HTTP %d  %s" % (st, body[:120]))
    print("FINAL: %s / %s" % (verdict.get("network"),
                              verdict.get("tracker_token")))
    json.dump({"gaid": gaid, "android_uuid": auuid, "reftag": referrer,
               "verdict": verdict},
              open(os.path.join(HERE, "golden_replay_run.json"), "w"),
              indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
