"""win_funnel2.py — the corrected FULLY-OFFLINE funnel (per-request signing).

Fixes vs win_phase_mint.py (which broke at sdk_click 500 / attribution 400):

 1. PER-REQUEST signing. The genuine app signs EVERY request separately with
    its own claims (the server binds blob<->request claims — slice A2/A4).
    win_phase_mint reused the session blob on sdk_click and /attribution.
    Now: session blob (kind=session claims), click blob (kind=click claims),
    attribution blob (kind=attribution claims) — each with its own second+S.
 2. Client-SDK header on EVERY request. Its omission caused the 400
    "unsupported sdk" on /attribution (slice 81: mandatory).
 3. Genuine click canonical wire shape (source/referrer_api/click_time_server/
    install_begin_time(+_server)/google_play_instant/...) instead of the
    session param set with a click_time bolted on.
 4. WIN head phase: request signings use (0x2B, 0x48)+CY@2 — the solved
    genuine phase for the three request signings (block_pattern_analysis).
 5. Device fingerprint cloned from the winning real run
    (app_session_params_real.json, app_version 3.14.0, not 3.13.9).
"""
import base64
import http.client
import json
import os
import random
import re
import struct
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_pipeline as M          # claims_for_law / finex_mint / VA_ORDER
import F as FP                     # region materializer
import adj9_full_chain as AF       # fmt (wire stamps)
from desc10_law import desc10_keys

HERE = os.path.dirname(os.path.abspath(__file__))

APP_TOKEN = "jut9tib0eeps"
CLIENT_SDK = "android5.7.0"
GEN_AUTH = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
SIGN_ID = "1500000"
HEADERS_ID = "10"
NATIVE_VERSION = "5.0.0"
WIN_HEAD = (0x2B, 0x48)            # solved genuine phase, request signings
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)"
CHROME_UA = ("Mozilla/5.0 (Linux; Android 12; moto g 42) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36")
OUT = os.path.join(HERE, "win_funnel2_result.json")

LOG = []


def log(msg):
    line = str(msg)
    print("[FUN2] %s" % line, flush=True)
    LOG.append(line)


# ---------------------------------------------------------------------------
# signing
# ---------------------------------------------------------------------------
def mint_auth(params, kind, head=WIN_HEAD):
    """One fresh signing for one request: own second, own S, own claims."""
    val = dict(params)
    val.update({
        "activity_kind": kind, "client_sdk": CLIENT_SDK,
        "adj_signing_id": SIGN_ID, "headers_id": HEADERS_ID,
        "native_version": NATIVE_VERSION, "adj_verification": GEN_AUTH,
    })
    missing = [k for k in desc10_keys(kind, val) if not val.get(k)]
    if missing:
        raise KeyError("%s claims missing: %s" % (kind, missing))

    sec = int(time.time())
    S = random.getrandbits(32)
    d0w, d2w, d4w = FP.region(S, 0, 0, head=head)
    padded, unpadded = M.claims_for_law(val, kind)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d2 = struct.pack(">I", d2w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    descs = [by[i] for i in M.VA_ORDER]
    blob, info = M.finex_mint(descs, sec)
    log("signed %-11s sec=%d S=%08x st=%s %dB" % (kind, sec, S, info["status"],
                                                  len(blob)))
    auth = ('Signature signature="%s",adj_signing_id="%s",algorithm="adj9",'
            'headers_id="%s",native_version="%s",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), SIGN_ID, HEADERS_ID,
               NATIVE_VERSION, GEN_AUTH))
    return auth, sec


def post(path, params, auth, method="POST"):
    body = urllib.parse.urlencode(params).encode()
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    conn.putrequest(method, path + ("" if method == "POST"
                                    else "?" + urllib.parse.urlencode(params)),
                    skip_host=1, skip_accept_encoding=1)
    for k, v in (("Client-SDK", CLIENT_SDK), ("Authorization", auth),
                 ("Content-Type", "application/x-www-form-urlencoded"),
                 ("User-Agent", UA), ("Host", "app.adjust.com"),
                 ("Connection", "Keep-Alive"), ("Accept-Encoding", "gzip"),
                 ("Content-Length", str(len(body) if method == "POST" else 0))):
        if method != "POST" and k in ("Content-Type", "Content-Length"):
            continue
        conn.putheader(k, v)
    conn.endheaders(body if method == "POST" else None)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8", "replace")
    conn.close()
    return resp.status, data


# ---------------------------------------------------------------------------
# funnel
# ---------------------------------------------------------------------------
def main():
    RES = {"log": LOG}
    # argv overrides: real device GAID + android_uuid for the re-attribution
    # story (farm_win-style: the adid already exists -> re-attributes to the
    # newest click). Without argv: fresh random identity, fresh-install story.
    real_gaid = len(sys.argv) > 1
    gps = sys.argv[1] if real_gaid else str(uuid.uuid4())
    auid = sys.argv[2] if len(sys.argv) > 2 else str(uuid.uuid4())
    log("gps=%s%s" % (gps, " (REAL DEVICE GAID)" if real_gaid else ""))
    RES["gps"] = gps
    RES["real_gaid"] = real_gaid

    base = json.load(open(os.path.join(HERE, "app_session_params_real.json"),
                          encoding="utf-8"))
    base.pop("push_token", None)

    # ---- 1. the click (python, chrome131 fingerprint) --------------------
    from curl_cffi import requests as cr
    s = cr.Session(impersonate="chrome131")
    click_url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0929"
                 "&creative=penti_generic&click_id=" + gps + "&idfa=" + gps
                 + "&gps_adid=" + gps)
    r = s.get(click_url, headers={"User-Agent": CHROME_UA},
              allow_redirects=False, timeout=30)
    loc = r.headers.get("Location", "")
    referrer = (urllib.parse.unquote(loc.split("referrer=", 1)[1])
                if "referrer=" in loc else None)
    log("click %d referrer=%s" % (r.status_code, (referrer or "NONE")[:60]))
    RES["click"] = {"http": r.status_code, "referrer": referrer}
    if not referrer:
        log("NO REFERRER - abort")
        json.dump(RES, open(OUT, "w"), indent=1)
        return 1
    t_click = time.time()

    def stamp(ts, ms=31):
        return AF.fmt(int(ts), ms).decode()

    # ---- 2. /session (own signing, session claims) ------------------------
    sp = dict(base)
    sp.update({
        "gps_adid": gps, "android_uuid": auid,
        "session_count": "1", "session_length": "0", "time_spent": "0",
        "subsession_count": "1", "first_error": "0", "last_error": "0",
        "retry_count": "0", "enqueue_size": "0",
        "created_at": stamp(t_click + 7, 61), "sent_at": stamp(t_click + 7, 68),
    })
    if real_gaid:
        # farm_win re-attribution story: installed_at/updated_at are the
        # package-manager firstInstallTime/lastUpdateTime (kept from BASE);
        # they predate the click exactly like the 10/10 device winners.
        log("installed_at=%s updated_at=%s (PM values, re-attribution story)"
            % (sp.get("installed_at"), sp.get("updated_at")))
    else:
        sp["installed_at"] = stamp(t_click + 7, 512)
        sp["updated_at"] = stamp(t_click + 7, 512)
    auth_s, _ = mint_auth(sp, "session")
    time.sleep(2)
    code, body = post("/session", sp, auth_s)
    log("SESSION %d %s" % (code, body[:120]))
    RES["session"] = {"http": code, "body": body[:300]}
    if code != 200:
        json.dump(RES, open(OUT, "w"), indent=1)
        return 1

    # ---- 3. /sdk_click (own signing, click claims, genuine wire shape) ----
    cp = {
        "app_token": APP_TOKEN, "device_type": sp["device_type"],
        "gps_adid": gps, "source": "install_referrer", "foreground": "1",
        "connectivity_type": sp["connectivity_type"],
        "cpu_type": sp["cpu_type"], "screen_size": sp["screen_size"],
        "gps_adid_src": sp["gps_adid_src"], "subsession_count": "1",
        "offline_mode_enabled": "0", "session_count": "1", "ui_mode": sp["ui_mode"],
        "gps_adid_attempt": "1", "session_length": "0", "referrer_api": "google",
        "time_spent": "0", "needs_response_details": "1",
        "screen_format": sp["screen_format"], "google_play_instant": "0",
        "android_uuid": auid, "referrer": referrer,
        "environment": "production", "attribution_deeplink": "1",
        "package_name": sp["package_name"], "os_name": "android",
        "tracking_enabled": "1", "api_level": sp["api_level"],
        "os_version": sp["os_version"], "device_name": sp["device_name"],
        "device_manufacturer": sp["device_manufacturer"],
        "hardware_name": sp["hardware_name"], "os_build": sp["os_build"],
        "app_version": sp["app_version"], "install_version": sp["app_version"],
        "language": sp["language"], "display_width": sp["display_width"],
        "display_height": sp["display_height"],
        "screen_density": sp["screen_density"],
        "created_at": stamp(t_click + 8, 24), "sent_at": stamp(t_click + 8, 31),
        "installed_at": sp["installed_at"],
        "updated_at": sp["updated_at"],
        "click_time": stamp(t_click, 0),
        "click_time_server": stamp(t_click - 2, 0),
        "install_begin_time": stamp(t_click + 6, 0),
        "install_begin_time_server": stamp(t_click + 4, 0),
        "activity_kind": "click",
    }
    auth_c, _ = mint_auth(cp, "click")
    time.sleep(2)
    code, body = post("/sdk_click", cp, auth_c)
    log("SDK_CLICK %d %s" % (code, body[:120]))
    RES["sdk_click"] = {"http": code, "body": body[:300]}
    if code != 200:
        json.dump(RES, open(OUT, "w"), indent=1)
        return 1

    # ---- 4. /attribution (own signing, attribution claims) ----------------
    ap = {
        "app_token": APP_TOKEN, "gps_adid": gps, "android_uuid": auid,
        "activity_kind": "attribution", "initiated_by": "sdk",
        "needs_response_details": "1", "environment": "production",
        "api_level": sp["api_level"], "app_version": sp["app_version"],
        "created_at": stamp(time.time(), 77), "device_name": sp["device_name"],
        "device_type": sp["device_type"], "gps_adid_src": sp["gps_adid_src"],
        "os_name": "android", "os_version": sp["os_version"],
        "package_name": sp["package_name"], "tracking_enabled": "1",
    }
    auth_a, _ = mint_auth(ap, "attribution")
    time.sleep(2)
    code, body = post("/attribution", ap, auth_a, method="GET")
    log("ATTRIBUTION %d %s" % (code, body[:200]))
    RES["attribution"] = {"http": code, "body": body[:600]}

    # ---- verdict ----------------------------------------------------------
    print("=" * 60, flush=True)
    try:
        j = json.loads(body)
        att = j.get("attribution") or {}
        net = att.get("network")
        if net and net != "Organic":
            print("*** FULLY OFFLINE NON-ORGANIC — GOAL ***")
            print("*** network=%s tracker=%s ***"
                  % (net, att.get("tracker_token")))
            RES["verdict"] = "NON-ORGANIC"
        elif code == 400 and "ask_in" in body:
            print("*** 400 ask_in — recognized-shape response ***")
            RES["verdict"] = "recognized-400"
        else:
            print("*** Organic — the python identity did not join the click ***")
            RES["verdict"] = "Organic"
    except Exception:
        print("*** attribution body not json ***")
        RES["verdict"] = "parse-error"
    print("=" * 60, flush=True)
    json.dump(RES, open(OUT if not real_gaid else
                        OUT.replace(".json", "_realgaid.json"), "w"), indent=1)
    print("saved %s" % (OUT if not real_gaid else
                        OUT.replace(".json", "_realgaid.json")), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
