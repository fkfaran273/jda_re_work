r"""manual_click.py — drive the user's MANUALLY-REGISTERED click.

The user clicked the tracker link by hand on a real Samsung SM-A366E and gave
us the resulting GAID and reftag.  That click is ALREADY registered server-side
under GAID 19267331-6e98-4668-9813-abdef0e1a613 with reftag cj1b5EDCPKvsb, so
we must NOT re-fire the link (that would mint a new click_id); we replay that
exact click into the install.

This differs from every prior run in three material ways:
  1. the click was registered by a REAL browser click, not by our own GET;
  2. the device is a Samsung SM-A366E / Android 15 / API 35 with a SIM
     (mcc 405, mnc 752, carrier Vi India) — we have been suppressing mcc/mnc
     for the SIM-less moto g42 profile all along;
  3. locale is en-IN / +0530, resolution 1080x2340, density 450dpi (xxhdpi).

Signature: the device-verified head (0x2b, 0x48) from DEVICE_SELECTORS.
"""
from __future__ import annotations
import base64, gzip, http.client, json, os, struct, sys, time
import urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M
import F as Fmod

# ---- the user's manual click, verbatim -------------------------------------
GAID = "19267331-6e98-4668-9813-abdef0e1a613"
REFTAG = ("adjust_reftag=cj1b5EDCPKvsb&utm_source=VKM+Digital+Yeni"
          "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")
APP_TOKEN = "jut9tib0eeps"
UA = ("Dalvik/2.1.0 (Linux; U; Android 15; SM-A366E "
      "Build/AP3A.240905.015.A2)")

# Samsung SM-A366E, Android 15, API 35, en-IN, +0530, SIM present (Vi India)
DEV = {
    "api_level": "35", "os_version": "15",
    "device_name": "SM-A366E", "device_manufacturer": "samsung",
    "hardware_name": "a36xq", "os_build": "AP3A.240905.015.A2",
    "app_version": "3.13.9", "install_version": "3.13.9",
    "language": "en", "mcc": "405", "mnc": "752",
    "display_width": "1080", "display_height": "2340",
    "screen_density": "xxhdpi",
}

OUT = os.path.join(HERE, "manual_click_result.json")
ADJ_V = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
OFF_MIN, OFF_LABEL = 330, "+0530"      # +05:30 India
S1_EXTRA = ("store_name_from_system", "initiating_package_name")


def fmt(ts, ms):
    import datetime
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=OFF_MIN))
    return dt.strftime("%%Y-%%m-%%dT%%H:%%M:%%S.%03dZ%s" % (ms, OFF_LABEL)).encode()


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


def auth_of(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_V))


def mint(params, kind, sec):
    claims = dict(params)
    for k, v in (("adj_verification", ADJ_V), ("adj_signing_id", "1500000"),
                 ("headers_id", "10"), ("native_version", "5.0.0"),
                 ("activity_kind", kind), ("client_sdk", "android5.7.0")):
        claims.setdefault(k, v)
    padded, unpadded = M.claims_for_law(claims, kind)
    d0w, d2w, d4w = Fmod.region(sec, M.DEFAULT_PID, 0,
                                head=M.DEVICE_SELECTORS)
    by = {0: (36, b"".join(w.to_bytes(4, "big") for w in d0w)),
          9: (5, bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")),
          8: (4, bytes.fromhex("bffffffffffffd1f0007000000000000")),
          4: (8, b"".join(w.to_bytes(4, "big") for w in d4w)),
          2: (1, d2w.to_bytes(4, "big")),
          7: (1, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, padded),
          5: (1, b"\0" * 4), 6: (1, b"\0" * 4), 1: (0, b""), 3: (0, b"")}
    blob, info = M.finex_mint([(by[i][0], 0, by[i][1]) for i in M.VA_ORDER], sec)
    return blob, info


def score(status, body):
    if status != 200:
        return "FAILURE (HTTP %d: %s)" % (status, body[:110])
    try:
        att = json.loads(body).get("attribution")
    except Exception:
        return "FAILURE (unparseable)"
    if not att:
        return "FAILURE (200, no attribution object)"
    net, tok = att.get("network"), att.get("tracker_token")
    if net and net != "Organic" and tok and tok != "wy7261z":
        return ("*** NON-ORGANIC: %s / %s / creative=%s ***"
                % (net, tok, att.get("creative")))
    return "ORGANIC (%s / %s / eng=%s)" % (net, tok, att.get("engagement_time"))


def main():
    gps = GAID
    auid = str(uuid.uuid4())
    t_click = int(time.time())
    sec = t_click + 6
    ins = fmt(sec - 55, 774).decode()
    tb = sec - 55 - 7
    rec = {"gps": gps, "auid": auid, "reftag": REFTAG,
           "head": [hex(x) for x in M.DEVICE_SELECTORS], "t_click": t_click}

    sp = dict(DEV)
    sp.update({"gps_adid": gps, "android_uuid": auid,
               "app_token": APP_TOKEN, "package_name": "com.penti.app",
               "environment": "production", "device_type": "phone",
               "gps_adid_src": "service", "foreground": "1",
               "connectivity_type": "1", "needs_response_details": "1",
               "attribution_deeplink": "1", "offline_mode_enabled": "0",
               "ui_mode": "1", "tracking_enabled": "1",
               "os_name": "android", "session_count": "1",
               "session_length": "0", "subsession_count": "1",
               "time_spent": "0",
               "store_name_from_system": "com.android.vending",
               "initiating_package_name": "com.android.vending",
               "created_at": fmt(sec - 1, 928).decode(),
               "sent_at": fmt(sec - 1, 942).decode(),
               "installed_at": ins, "updated_at": ins,
               "gps_adid_attempt": "1"})
    print("SESSION params: %d keys" % len(sp), flush=True)
    bs, isess = mint(sp, "session", sec)
    print("  mint status:", isess.get("status"), flush=True)
    st, bd = req("POST", "/session", sp, auth_of(bs))
    rec["session"] = [st, bd[:220]]
    print("  SESSION: %d %s" % (st, bd[:200]), flush=True)

    time.sleep(3)
    cp = {k: v for k, v in sp.items() if k not in S1_EXTRA}
    cp.update({"referrer": REFTAG, "source": "install_referrer",
               "referrer_api": "google", "google_play_instant": "0",
               "install_version": DEV["install_version"],
               "created_at": fmt(sec, 961).decode(),
               "sent_at": fmt(sec, 970).decode(),
               "click_time": fmt(t_click, 0).decode(),
               "click_time_server": fmt(t_click - 2, 0).decode(),
               "install_begin_time": fmt(tb, 0).decode(),
               "install_begin_time_server": fmt(tb - 2, 0).decode()})
    print("CLICK params: %d keys" % len(cp), flush=True)
    bc, iclick = mint(cp, "click", sec)
    print("  mint status:", iclick.get("status"), flush=True)
    stc, bdc = req("POST", "/sdk_click", cp, auth_of(bc))
    rec["sdk_click"] = [stc, bdc[:220]]
    print("  SDK_CLICK: %d %s" % (stc, bdc[:200]), flush=True)

    for w in (10, 30, 60, 120, 180):
        time.sleep(w)
        ap = {"initiated_by": "backend", "gps_adid_attempt": "1",
              "api_level": DEV["api_level"], "app_version": DEV["app_version"],
              "app_token": APP_TOKEN, "os_version": DEV["os_version"],
              "created_at": fmt(sec, 666).decode(), "device_type": "phone",
              "gps_adid": gps, "foreground": "1", "android_uuid": auid,
              "sent_at": fmt(sec, 696).decode(),
              "offline_mode_enabled": "0", "device_name": DEV["device_name"],
              "environment": "production", "needs_response_details": "1",
              "attribution_deeplink": "1", "package_name": "com.penti.app",
              "os_name": "android", "ui_mode": "1",
              "gps_adid_src": "service", "tracking_enabled": "1"}
        ba, _ = mint(ap, "attribution", int(time.time()))
        sa, bda = req("GET", "/attribution", ap, auth_of(ba))
        v = score(sa, bda)
        print("  ATTRIBUTION +%ds: %s" % (w, v), flush=True)
        rec["last"] = [sa, bda[:400]]
        rec["verdict"] = v
        if "NON-ORGANIC" in v:
            break
    json.dump(rec, open(OUT, "w"), indent=1)
    print("\n=== VERDICT ===")
    print("  %s" % rec.get("verdict"))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
