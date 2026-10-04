"""arm_tls_cffi.py — isolate the TLS/HTTP client-stack fingerprint.

The one variable never held constant between every winning run (the app,
Conscrypt/OkHttp stack) and every losing run (PC OpenSSL via http.client,
or AOSP curl via adb shell): the TLS ClientHello / HTTP-stack fingerprint
of the /session, /sdk_click and /attribution connections.

Three parallel arms, identical except for the transport client of the three
signed Adjust calls:

  arm O  "openssl"     — control: FC.send (http.client, CPython OpenSSL,
                         no ALPN, HTTP/1.1).  Expected: Organic (replicates
                         ARM C / F_FIX / TRANSPORT2 shape).
  arm C1 "chrome_android" — curl_cffi impersonate="chrome131_android"
                         (real Android BoringSSL hello + Android h2
                         settings, but Chrome-flavoured).
  arm C2 "conscrypt"   — curl_cffi with a hand-set JA3 (published OkHttp/
                         Conscrypt Android fingerprint) + OkHttp akamai
                         (h2 settings 4:16777216, window 16711680,
                         pseudo-header order m,p,a,s).  BEST EFFORT — the
                         app's true hello was never captured (the SAZ legs
                         are Fiddler-MITM'd); a negative here is weak
                         evidence, a positive is decisive.

Everything else is the ARM-C recipe: fresh GAID per arm, PC tracker click
with the moto g42 UA, real 217.431 s CTIT, mint_pipeline F.py-minted
blobs, moto g42 profile, Play-referrer placeholder on sdk_click.

Fingerprint pre-flight: both cffi arms first hit tls.peet.ws/api/all so the
actual ClientHello/HTTP2 seen on the wire is logged next to the intent.
Every request/response is logged to arm_tls_cffi_result.json.
"""
import base64
import datetime
import json
import os
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mint_pipeline as M
import run_funnel as RF
import adj9_full_chain as FC
from curl_cffi import requests as CR

PROFILE = json.load(open(os.path.join(HERE, "moto_g42_profile.json")))
CTIT_INSTALL = 217.431
CTIT_BEGIN = 210.0
OUT = os.path.join(HERE, "arm_tls_cffi_result.json")

FC.DEV = dict(PROFILE["DEV"])
FC.UA = PROFILE["UA"]
FC.OFF_MINUTES, FC.OFF_LABEL = PROFILE["OFF_MINUTES"], PROFILE["OFF_LABEL"]
FC.ADD_IDFA = PROFILE["ADD_IDFA"]
FC.USE_PROXY = False
FC.USE_DEVICE = False

PLAY_REFERRER = "utm_source=(not%20set)&utm_medium=(not%20set)"

# Best-effort Conscrypt/OkHttp Android ClientHello (published JA3 form).
# (52394/0xCCAA + the 493xx CCM-8 block dropped: curl_cffi's cipher map
#  doesn't know them; the rest is the published OkHttp/Conscrypt set.)
CONSCRYPT_JA3 = (
    "771,4866-4867-4865-49196-49200-49195-49199-52393-52392-159-158-"
    "4865-49188-49192-49187-49191-49162-49172-49161-49171-51-57-47-53-10,"
    "0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0")
OKHTTP_AKAMAI = "4:16777216|16711680|0|m,p,a,s"

LOG = []


def log(entry):
    entry["t"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    LOG.append(entry)
    print("[log] %s %s -> %s" % (entry.get("arm"), entry.get("what"),
                                 str(entry.get("status"))), flush=True)


def make_sessions():
    return {
        "chrome_android": CR.Session(impersonate="chrome131_android"),
        "conscrypt": CR.Session(ja3=CONSCRYPT_JA3, akamai=OKHTTP_AKAMAI),
    }


def preflight(sess):
    for arm, s in sess.items():
        try:
            r = s.get("https://tls.peet.ws/api/all", timeout=30)
            j = r.json()
            log({"arm": arm, "what": "preflight tls.peet.ws",
                 "status": r.status_code,
                 "ja3": j.get("tls", {}).get("ja3"),
                 "ja3_hash": j.get("tls", {}).get("ja3_hash"),
                 "akamai": j.get("http2", {}).get("akamai_fingerprint"),
                 "http_version": j.get("http_version"),
                 "peet": j.get("tls", {}).get("peetprint_hash")})
        except Exception as e:
            log({"arm": arm, "what": "preflight tls.peet.ws",
                 "status": "ERR", "error": str(e)[:300]})


def cffi_send(arm, s, url, params, blob, method="POST"):
    auth = FC._auth_header(blob)
    headers = {"Client-SDK": "android5.7.0"}
    if auth:
        headers["Authorization"] = auth
    if method == "POST":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["User-Agent"] = FC.UA
    try:
        if method == "POST":
            body = urllib.parse.urlencode(params)
            r = s.post(url, data=body, headers=headers, timeout=45)
        else:
            r = s.get(url, params=params, headers=headers, timeout=45)
        log({"arm": arm, "what": "%s %s" % (method, url.rsplit("/", 1)[-1]),
             "status": r.status_code, "resp": r.text[:400]})
        return r.status_code, r.text
    except Exception as e:
        log({"arm": arm, "what": "%s %s" % (method, url.rsplit("/", 1)[-1]),
             "status": "ERR", "error": str(e)[:300]})
        return "ERR", str(e)[:200]


REAL_SEND = FC.send
SESS = {}


def send_dispatch(url, params, blob, method="POST"):
    arm = send_dispatch.arm
    if arm == "openssl":
        st, body = REAL_SEND(url, params, blob, method)
        log({"arm": arm, "what": "%s %s" % (method, url.rsplit("/", 1)[-1]),
             "status": st, "resp": str(body)[:400]})
        return st, body
    return cffi_send(arm, SESS[arm], url, params, blob, method)


send_dispatch.arm = "openssl"
FC.send = send_dispatch

CLICK_DEV = {
    "locale": {"language": "tr", "country": "TR"},
    "User-Agent": FC.UA,
    "os_version": PROFILE["DEV"]["os_version"],
    "model": PROFILE["DEV"]["device_name"],
    "build": PROFILE["DEV"]["os_build"],
    "mcc": "", "mnc": "",
}

ARMS = ["openssl", "chrome_android", "conscrypt"]
if "--only" in sys.argv:
    ARMS = [a for a in sys.argv[sys.argv.index("--only") + 1].split(",")
            if a]




def main():
    res = {"arms": {}, "note": "transport-fingerprint isolation; see docstring"}
    state = {}

    # ---- STEP 1: one click per arm (click transport is not under test) ----
    for arm in ARMS:
        gps, link = M._fresh_gps_link(RF.LINK)
        auid = str(uuid.uuid4())
        t0 = time.time()
        ref, hop = RF.click_tracker(link, gps, FC.UA, CLICK_DEV)
        log({"arm": arm, "what": "click", "status": "302?",
             "reftag": (ref or "")[:80]})
        state[arm] = {"gps": gps, "auid": auid, "t_click": t0, "ref": ref}
        res["arms"][arm] = {"gps": gps, "auid": auid,
                            "reftag": (ref or "").split("adjust_reftag=", 1)[-1]
                            .split("&")[0] if ref and "adjust_reftag=" in ref
                            else None}
        time.sleep(2)

    # ---- STEP 2: real CTIT ----
    earliest = min(s["t_click"] for s in state.values())
    wait = CTIT_INSTALL - (time.time() - earliest)
    if wait > 0:
        print("[tls] waiting %.0fs for CTIT..." % wait, flush=True)
        time.sleep(wait)

    # ---- STEP 3+4: session + sdk_click per arm ----
    for arm in ARMS:
        st_ = state[arm]
        send_dispatch.arm = arm
        ins = FC.fmt(int(st_["t_click"]) + int(CTIT_INSTALL), 431)
        tb = st_["t_click"] + CTIT_BEGIN
        s2, r2 = M.api_session_mint(st_["gps"], st_["auid"], ins)
        r2 = r2.decode("utf-8", "replace") if isinstance(r2, bytes) else r2
        res["arms"][arm]["session"] = [s2, str(r2)[:300]]
        json.dump(res, open(OUT, "w"), indent=1)
        time.sleep(3)
        s1, r1 = M.api_sdk_click_mint(st_["gps"], st_["auid"], PLAY_REFERRER,
                                      int(st_["t_click"]), tb, ins)
        r1 = r1.decode("utf-8", "replace") if isinstance(r1, bytes) else r1
        res["arms"][arm]["sdk_click"] = [s1, str(r1)[:300]]
        json.dump(res, open(OUT, "w"), indent=1)
        time.sleep(3)

    # ---- STEP 5: attribution polls, 3 rounds, all arms per round ----
    time.sleep(8)
    for rnd in range(3):
        for arm in ARMS:
            st_ = state[arm]
            send_dispatch.arm = arm
            code, body = M.api_attribution_mint(st_["gps"], st_["auid"],
                                                "pt-" + st_["auid"][:8],
                                                "backend")
            body = body.decode("utf-8", "replace") if isinstance(body, bytes) \
                else body
            try:
                a = json.loads(body).get("attribution", {})
            except Exception:
                a = {}
            eng = a.get("engagement_time")
            joined = bool(eng) and not eng.startswith("0001-01-01")
            res["arms"][arm].setdefault("verdicts", []).append(
                {"round": rnd + 1, "status": code,
                 "token": a.get("tracker_token"), "network": a.get("network"),
                 "engagement_time": eng, "joined": joined,
                 "installed_at": a.get("installed_at")})
            print("  [%s] poll %d: %s token=%s network=%s eng=%s %s"
                  % (arm, rnd + 1, code, a.get("tracker_token"),
                     a.get("network"), eng,
                     "JOINED" if joined else "organic"), flush=True)
            res["arms"][arm]["JOINED"] = any(
                v["joined"] for v in res["arms"][arm]["verdicts"])
            json.dump(res, open(OUT, "w"), indent=1)
        if rnd < 2:
            time.sleep(20)

    res["request_log"] = LOG
    json.dump(res, open(OUT, "w"), indent=1)
    print("\n==== VERDICTS ====")
    for arm in ARMS:
        print("  %-15s %s" % (arm, "NON-ORGANIC (JOINED)"
                                if res["arms"][arm].get("JOINED")
                                else "Organic"))
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    if "--preflight-only" in sys.argv:
        SESS.update(make_sessions())
        preflight(SESS)
        json.dump({"request_log": LOG}, open(OUT, "w"), indent=1)
        sys.exit(0)
    SESS.update(make_sessions())
    preflight(SESS)
    main()
