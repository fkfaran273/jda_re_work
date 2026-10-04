#!/usr/bin/env python3
r"""transport_test.py — which Python/PC HTTP transport gets a KNOWN-GOOD adj9
signature blob recognized by app.adjust.com?

Source of truth: transport_capture_log.txt — the module's capture from a genuine
signing session (gps_adid 363e5b78-8670-4c50-8348-9f87c604111b, app launched
after wipe+click at 2026-09-27T19:24:47..51Z+0530).  It contains 6 `sign_input`
records (the claims maps that produced each blob) and 6 `authorization_header`
records (the base64 blobs in signing order).

  row 0 = session      <-- the session signing (first thing after wipe+launch)
  row 1 = click
  row 2 = session      (older identity 2db6422f, 09-24)
  row 3 = click        (older identity 2db6422f, 09-24)
  row 4 = attribution  (older identity 2db6422f, 09-24)
  row 5 = attribution  <-- the sharp probe for identity 363e5b78

Everything is held CONSTANT across arms except the transport: same blob, same
params, same header set.  A difference in verdict is therefore a transport
effect, nothing else.

Arms
  A    python stdlib http.client.HTTPSConnection      (baseline, CPython TLS)
  A2   same but hand-rolled HTTP/1.0 request line (raw header order)
  B    curl_cffi  impersonate=chrome131_android       (the Android fingerprint)
  B2   curl_cffi  impersonate=chrome99_android        (older android control)
  B3   curl_cffi  impersonate=chrome131 (desktop TLS/H1)
  B4   curl_cffi  impersonate=chrome124
  B5   curl_cffi  impersonate=chrome119
  C    tls_client  okhttp4_android_12                 (OkHttp4-on-Android-12)
  C2   tls_client  okhttp4_android_13
  C3   tls_client  chrome_120
  D    device curl via `adb shell curl`              (control: the phone's own
                                                      network stack + its IP)
  FLIP  genuine blob with byte0 bit0 flipped         (control: MUST not pass)
  NOAUTH no Authorization header at all              (control: MUST not pass)

Reading the answer
  PASS      = response JSON contains "ask_in"        -> signature verified
  FAIL      = attribution is tracker_name=Organic with
              engagement_time=0001-01-01T00:00:00Z   -> Organic fallback
  GATE      = HTTP 400 "Ignoring too frequent session" -> the record EXISTS
              server-side (identity already booked), signature path not judged

Usage
  python transport_test.py extract        # parse capture, print summary only
  python transport_test.py attr           # GET /attribution replay (sharp)
  python transport_test.py session        # POST /session replay
  python transport_test.py all
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)

CAPTURE = os.path.join(HERE, "transport_capture_log.txt")
OUTDIR = os.path.join(HERE, "transport")
TARGET_GPS = "363e5b78-8670-4c50-8348-9f87c604111b"   # from transport_identity.json

HOST = "app.adjust.com"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)"
CLIENT_SDK = "android5.7.0"
DEVICE_SERIAL = os.environ.get("ANDROID_SERIAL", "ZD2228MY3X")
ADB = os.environ.get("ADB", "adb")
ADJ_VERIFICATION = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"

# The app's OWN wire order for this /session, read straight out of
# transport_capture_log.txt line 2339 (the ActivityPackageSender param dump,
# 43 keys, BEFORE the 7 signing keys are appended).  This is byte-faithful for
# the moto g42 session; the SESSION_ORDER list below is the older DN2101
# order recovered from fiddler/pentindroid_logs.saz and is kept only as an
# ablation arm ("X").
SESSION_WIRE_ORDER = [
    "store_name_from_system", "gps_adid_attempt", "api_level", "hardware_name",
    "app_version", "app_token", "installed_at", "created_at", "wait_total",
    "device_type", "language", "gps_adid", "foreground", "connectivity_type",
    "device_manufacturer", "display_width", "device_name",
    "needs_response_details", "os_build", "updated_at", "cpu_type",
    "retry_count", "screen_size", "screen_format", "last_error",
    "gps_adid_src", "wait_time", "os_version", "first_error", "android_uuid",
    "sent_at", "offline_mode_enabled", "environment", "screen_density",
    "attribution_deeplink", "session_count", "display_height", "package_name",
    "initiating_package_name", "os_name", "ui_mode", "enqueue_size",
    "tracking_enabled",
]
# older DN2101 order (SAZ) — ablation only
SESSION_ORDER = [
    "store_name_from_system", "gps_adid_attempt", "app_token", "wait_total",
    "device_type", "gps_adid", "foreground", "connectivity_type",
    "needs_response_details", "cpu_type", "retry_count", "screen_size",
    "screen_format", "last_error", "gps_adid_src", "wait_time", "first_error",
    "android_uuid", "offline_mode_enabled", "environment", "attribution_deeplink",
    "session_count", "package_name", "initiating_package_name", "os_name",
    "ui_mode", "enqueue_size", "tracking_enabled", "api_level", "os_version",
    "device_name", "device_manufacturer", "hardware_name", "os_build",
    "app_version", "language", "display_width", "display_height",
    "screen_density", "created_at", "sent_at", "installed_at", "updated_at",
]
# keys that live in the Authorization header, never in the body
CANON_ONLY = {"activity_kind", "client_sdk", "adj_verification",
              "headers_id", "adj_signing_id", "native_version", "algorithm"}


# ------------------------------------------------------------------ parsing
def auth_header(blob_b64: str) -> str:
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (blob_b64, ADJ_VERIFICATION))


def parse_capture(path: str = CAPTURE):
    """-> list of {row, kind, gps_adid, android_uuid, created_at, claims,
                   order, blob_b64, key2_hex, auth}  in signing order."""
    txt = open(path, encoding="utf-8", errors="replace").read()
    blocks = re.findall(
        r"###ADJ9_BEGIN type=sign_input[^\n]*\n(.*?)\n###ADJ9_END", txt, re.S)
    auths = re.findall(
        r"###ADJ9_BEGIN type=authorization_header[^\n]*\ntext: ([^\n]*)", txt)
    rows = []
    for i, b in enumerate(blocks):
        s = k = None
        order = []
        for line in b.split("\n"):
            if line.startswith("map_toString="):
                s = line[len("map_toString="):].lstrip("{")
            elif line.startswith("map_order="):
                # the module writes  key\x01value \x02 key\x01value ...
                order = [pair.split("\x01")[0]
                         for pair in line[len("map_order="):].split("\x02")
                         if "\x01" in pair]
            elif line.startswith("key2_hex="):
                k = line[len("key2_hex="):]
        claims = {}
        for item in s.split(", "):
            kk, _, vv = item.partition("=")
            claims[kk] = vv
        blob_b64 = None
        auth = auths[i] if i < len(auths) else None
        if auth:
            blob_b64 = re.search(r'signature="([^"]+)"', auth).group(1)
        if not order:
            order = list(claims)
        rows.append({
            "row": i, "kind": claims.get("activity_kind", "?"),
            "gps_adid": claims.get("gps_adid"),
            "android_uuid": claims.get("android_uuid"),
            "created_at": claims.get("created_at"),
            "claims": claims, "order": order,
            "blob_b64": blob_b64, "key2_hex": k, "auth": auth,
        })
    return rows


def pick(rows, kind, gps=TARGET_GPS):
    for r in rows:
        if r["kind"] == kind and r["gps_adid"] == gps:
            return r
    for r in rows:
        if r["kind"] == kind:
            return r
    raise SystemExit("no %s row in capture" % kind)


def wire_query(claims: dict, order=None) -> str:
    keys = [k for k in (order if order else claims) if k in claims
            and k not in CANON_ONLY]
    seen, out = set(), []
    for k in keys:
        if k in seen:
            continue
        seen.add(k)
        out.append("%s=%s" % (urllib.parse.quote(k, safe=""),
                              urllib.parse.quote(claims[k], safe="")))
    return "&".join(out)


# ---------------------------------------------------------------- transports
def send_httpclient(method, path, blob_b64, body=None, http10=False):
    t0 = time.time()
    c = http.client.HTTPSConnection(HOST, timeout=40)
    hdrs = [("Client-SDK", CLIENT_SDK), ("User-Agent", UA)]
    if body is not None:
        hdrs += [("Content-Type", "application/x-www-form-urlencoded"),
                 ("Content-Length", str(len(body.encode())))]
    if blob_b64 is not None:
        hdrs.append(("Authorization", auth_header(blob_b64)))
    hdrs += [("Host", HOST), ("Connection", "Keep-Alive"),
             ("Accept-Encoding", "identity")]
    b = body.encode() if body is not None else None
    if http10:
        c.putrequest(method, path, skip_host=1, skip_accept_encoding=1)
        for k, v in hdrs:
            c.putheader(k, v)
        c.endheaders(b)
    else:
        c.request(method, path, body=b, headers=dict(hdrs))
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data.decode("utf-8", "replace"), time.time() - t0


def send_exact(method, path, blob_b64, body=None, ua=UA, http10=True):
    """Arm E — the app's EXACT header profile, taken from the genuine Fiddler
    capture `fiddler/pentindroid_logs.saz` (raw/1_c.txt, a real /session):

        <METHOD> <url> HTTP/1.1
        Client-SDK: android5.7.0
        Authorization: Signature ...
        Content-Type: application/x-www-form-urlencoded     (POST only)
        User-Agent: Dalvik/2.1.0 (Linux; U; Android 11; DN2101 ...)
        Host: app.adjust.com
        Connection: Keep-Alive
        Accept-Encoding: gzip                                 <-- NOT identity
        Content-Length: <n>                                   (POST only)

    i.e. same names and casings as every other arm, but the ORDER is the app's
    and Accept-Encoding is gzip.  Nothing else changes.
    """
    t0 = time.time()
    c = http.client.HTTPSConnection(HOST, timeout=40)
    hdrs = [("Client-SDK", CLIENT_SDK)]
    if blob_b64 is not None:
        hdrs.append(("Authorization", auth_header(blob_b64)))
    if body is not None:
        hdrs.append(("Content-Type", "application/x-www-form-urlencoded"))
    hdrs.append(("User-Agent", ua))
    hdrs += [("Host", HOST), ("Connection", "Keep-Alive"),
             ("Accept-Encoding", "gzip")]
    if body is not None:
        hdrs.append(("Content-Length", str(len(body.encode()))))
    b = body.encode() if body is not None else None
    if http10:
        c.putrequest(method, path, skip_host=1, skip_accept_encoding=1)
        for k, v in hdrs:
            c.putheader(k, v)
        c.endheaders(b)
    else:
        c.request(method, path, body=b, headers=dict(hdrs))
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data.decode("utf-8", "replace"), time.time() - t0


def send_curl_cffi(method, path, blob_b64, body=None,
                   impersonate="chrome131_android"):
    from curl_cffi import requests as cr
    t0 = time.time()
    hdrs = {"Client-SDK": CLIENT_SDK, "User-Agent": UA,
            "Accept-Encoding": "identity", "Connection": "Keep-Alive"}
    if body is not None:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    if blob_b64 is not None:
        hdrs["Authorization"] = auth_header(blob_b64)
    url = "https://%s%s" % (HOST, path)
    if method == "POST":
        r = cr.post(url, headers=hdrs, content=body.encode(),
                    impersonate=impersonate, timeout=40)
    else:
        r = cr.get(url, headers=hdrs, impersonate=impersonate, timeout=40)
    return r.status_code, r.text, time.time() - t0


def send_tls_client(method, path, blob_b64, body=None,
                    identifier="okhttp4_android_12"):
    import tls_client
    t0 = time.time()
    s = tls_client.Session(client_identifier=identifier,
                           random_tls_extension_order=True)
    hdrs = {"Client-SDK": CLIENT_SDK, "User-Agent": UA,
            "Accept-Encoding": "identity"}
    if body is not None:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    if blob_b64 is not None:
        hdrs["Authorization"] = auth_header(blob_b64)
    url = "https://%s%s" % (HOST, path)
    if method == "POST":
        r = s.post(url, headers=hdrs, data=body.encode())
    else:
        r = s.get(url, headers=hdrs)
    return r.status_code, r.text, time.time() - t0


def send_device_curl(method, path, blob_b64, body=None):
    """The CONTROL: the request leaves from the phone (its IP, its TLS stack)."""
    t0 = time.time()
    parts = ["curl", "-s", "-S", "-k", "--max-time", "60",
             "-X", method, "-w", "\\n###HTTP:%{http_code}",
             "-H", "'Client-SDK: " + CLIENT_SDK + "'",
             "-H", "'User-Agent: " + UA + "'",
             "-H", "'Accept-Encoding: identity'"]
    if body is not None:
        parts += ["-H", "'Content-Type: application/x-www-form-urlencoded'",
                  "--data-raw", "'" + body + "'"]
    if blob_b64 is not None:
        parts += ["-H", "'Authorization: " + auth_header(blob_b64) + "'"]
    parts += ["'https://" + HOST + path + "'"]
    script = " ".join(parts)
    # push the script to the device (no shell-quoting layers can mangle it)
    tmp = os.path.join(HERE, "transport", "_tt.sh")
    os.makedirs(os.path.dirname(tmp), exist_ok=True)
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(script + "\n")
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    subprocess.run([ADB, "-s", DEVICE_SERIAL, "push", tmp,
                    "/data/local/tmp/tt.sh"], env=env,
                   capture_output=True, text=True, timeout=90)
    out = subprocess.run([ADB, "-s", DEVICE_SERIAL, "shell",
                          "sh /data/local/tmp/tt.sh"],
                         capture_output=True, text=True, timeout=150)
    txt = out.stdout + (("\n[stderr] " + out.stderr) if out.stderr else "")
    m = re.search(r"###HTTP:(\d{3})", txt)
    status = int(m.group(1)) if m else 0
    body_txt = txt[: m.start()] if m else txt
    # toybox curl can leave stray chars around the body; keep JSON only
    body_txt = body_txt.strip()
    if body_txt.startswith("{"):
        body_txt = body_txt[:body_txt.rindex("}") + 1]
    return status, body_txt, time.time() - t0


TRANSPORTS = {
    "A":     lambda m, p, b, body: send_httpclient(m, p, b, body),
    "A2":    lambda m, p, b, body: send_httpclient(m, p, b, body, http10=True),
    "E":     lambda m, p, b, body: send_exact(m, p, b, body),
    "E2":    lambda m, p, b, body: send_exact(m, p, b, body, http10=False),
    "B":     lambda m, p, b, body: send_curl_cffi(m, p, b, body, "chrome131_android"),
    "B2":    lambda m, p, b, body: send_curl_cffi(m, p, b, body, "chrome99_android"),
    "B3":    lambda m, p, b, body: send_curl_cffi(m, p, b, body, "chrome131"),
    "B4":    lambda m, p, b, body: send_curl_cffi(m, p, b, body, "chrome124"),
    "B5":    lambda m, p, b, body: send_curl_cffi(m, p, b, body, "chrome119"),
    "C":     lambda m, p, b, body: send_tls_client(m, p, b, body, "okhttp4_android_12"),
    "C2":    lambda m, p, b, body: send_tls_client(m, p, b, body, "okhttp4_android_13"),
    "C3":    lambda m, p, b, body: send_tls_client(m, p, b, body, "chrome_120"),
    "D":     send_device_curl,
    "FLIP":  lambda m, p, b, body: send_httpclient(m, p, b, body),
    "NOAUTH": lambda m, p, b, body: send_httpclient(m, p, b, body),
}
ARM_OF = {"FLIP": "E", "NOAUTH": "E"}


# ------------------------------------------------------------------ judging
def classify(status, body):
    """-> (verdict, note)  PASS / FAIL / GATE / RESP / OTHER"""
    try:
        j = json.loads(body)
    except Exception:
        return "OTHER", body[:160].replace("\n", " ")
    if "ask_in" in j:
        return "PASS(recognized)", "ask_in=%s adid=%s" % (j["ask_in"],
                                                        j.get("adid", "?"))
    if "attribution" in j:
        a = j["attribution"]
        if a.get("tracker_name") == "Organic" and \
           str(a.get("engagement_time", "")).startswith("0001-01-01"):
            v = "FAIL(Organic)"
        else:
            v = "RESP(non-organic)"
        return v, ("tracker=%s network=%s eng=%s installed=%s"
                   % (a.get("tracker_token"), a.get("network"),
                      str(a.get("engagement_time"))[:19], a.get("installed_at")))
    if "error" in j:
        e = j["error"]
        if "too frequent" in e or "check interval" in e:
            m = re.search(r"interval: (\S+?), min interval", e)
            return "GATE(400 exists)", "min-interval gate, gap=%s" % (
                m.group(1) if m else "?")
        if "signature" in e.lower():
            return "REJECT(sig)", e[:160]
        return "GATE(err)", e[:160]
    if "adid" in j:
        return "RESP(no ask_in)", body[:150]
    return "OTHER", body[:150].replace("\n", " ")


def summarize(tag, status, body, elapsed):
    verdict, note = classify(status, body)
    print("  %-7s HTTP %-4s %6.2fs  %-16s %s"
          % (tag, status, elapsed, verdict, note))
    return {"tag": tag, "status": status, "verdict": verdict, "note": note,
            "body": body[:1500]}


def paired_session(order=("A", "D", "E", "B", "C", "FLIP"), row_index=0,
                   max_wait_min=75, wire_order="native", outfile=None):
    """One transport per shot, on the SAME identity, waiting out the server's
    20-minute "Ignoring too frequent session" gate between shots.

    The gate is NOT blob-gated (the FLIP/NOAUTH controls hit it too), so a
    gated reply tells us nothing about the signature — we simply wait it out.
    Every shot that finally lands is a clean, judged verdict.
    """
    rows = parse_capture()
    sess = [r for r in rows if r["gps_adid"] == TARGET_GPS
            and r["kind"] == "session"][row_index]
    if wire_order == "native":
        order_keys = [k for k in SESSION_WIRE_ORDER if k in sess["claims"]]
    else:
        order_keys = [k for k in SESSION_ORDER if k in sess["claims"]]
    order_keys += [k for k in sess["order"]
                   if k in sess["claims"] and k not in order_keys]
    body = wire_query(sess["claims"], order_keys)
    blob = sess["blob_b64"]
    flip = bytearray(base64.b64decode(blob)); flip[0] ^= 1
    blobs = {"FLIP": base64.b64encode(bytes(flip)).decode(), "NOAUTH": None}
    print("paired session probe on identity %s (gps=%s, created=%s)"
          % (sess["row"], sess["gps_adid"], sess["created_at"]))
    out = []
    for tag in order:
        b = blobs.get(tag, blob)
        arm = ARM_OF.get(tag, tag)
        t0 = time.time()
        waited = 0.0
        while True:
            print("[%s] shot (waited %.0fs)" % (tag, waited), flush=True)
            try:
                st, txt, el = TRANSPORTS[arm]("POST", "/session", b, body)
            except Exception as e:
                st, txt, el = 0, "%s: %s" % (type(e).__name__, e), 0.0
            v, n = classify(st, txt)
            if not v.startswith("GATE") or waited > max_wait_min * 60:
                break
            print("    gated -> waiting 90s for the 20m gate to clear", flush=True)
            time.sleep(90)
            waited += 90
        r = summarize(tag, st, txt, el)
        r["waited_s"] = round(waited, 1)
        r["gps_adid"] = sess["gps_adid"]
        r["transport"] = arm
        out.append(r)
        if outfile:
            os.makedirs(os.path.dirname(outfile), exist_ok=True)
            json.dump(out, open(outfile, "w"), indent=1)
        time.sleep(5)
    print("\n== PAIRED SESSION SUMMARY ==")
    for r in out:
        print("  %-7s %-5s %-16s waited=%-6s %s"
              % (r["tag"], r["status"], r["verdict"], r["waited_s"],
                 r["note"][:70]))
    passed = [r["tag"] for r in out if r["verdict"].startswith("PASS")]
    print("\n  PASSING TRANSPORTS: %s" % (passed or "NONE"))
    return out


def run_plan(plan, method, path, body, outfile):
    rows = []
    for tag, blob_b64, desc in plan:
        arm = ARM_OF.get(tag, tag)
        print("[%s] %s" % (tag, desc))
        try:
            st, txt, el = TRANSPORTS[arm](method, path, blob_b64, body)
        except Exception as e:
            st, txt, el = 0, "%s: %s" % (type(e).__name__, e), 0.0
        rows.append(summarize(tag, st, txt, el))
        time.sleep(3)
    if outfile:
        os.makedirs(os.path.dirname(outfile), exist_ok=True)
        json.dump(rows, open(outfile, "w"), indent=1)
        print("saved", outfile)
    print("\n== SUMMARY (%s) ==" % method)
    for r in rows:
        print("  %-7s %-5s %-16s %s"
              % (r["tag"], r["status"], r["verdict"], r["note"][:90]))
    passed = [r["tag"] for r in rows if r["verdict"].startswith("PASS")]
    print("\n  PASSING ARMS: %s" % (passed or "NONE"))
    return rows


def standard_plan(blob_b64):
    flip = bytearray(base64.b64decode(blob_b64))
    flip[0] ^= 1
    flip_b64 = base64.b64encode(bytes(flip)).decode()
    return [
        ("A",      blob_b64, "genuine blob | stdlib http.client"),
        ("B",      blob_b64, "genuine blob | curl_cffi chrome131_android"),
        ("C",      blob_b64, "genuine blob | tls_client okhttp4_android_12"),
        ("D",      blob_b64, "genuine blob | DEVICE curl (phone IP + TLS)"),
        ("E",      blob_b64, "genuine blob | EXACT app header order + AE:gzip"),
        ("E2",     blob_b64, "genuine blob | EXACT order via http.client 1.1"),
        ("B2",     blob_b64, "genuine blob | curl_cffi chrome99_android"),
        ("C2",     blob_b64, "genuine blob | tls_client okhttp4_android_13"),
        ("B3",     blob_b64, "genuine blob | curl_cffi chrome131 (desktop)"),
        ("B4",     blob_b64, "genuine blob | curl_cffi chrome124"),
        ("B5",     blob_b64, "genuine blob | curl_cffi chrome119"),
        ("C3",     blob_b64, "genuine blob | tls_client chrome_120"),
        ("A2",     blob_b64, "genuine blob | http.client raw HTTP/1.0"),
        ("FLIP",   flip_b64, "CONTROL genuine params, blob byte0 bit0 flipped"),
        ("NOAUTH", None,     "CONTROL no Authorization header at all"),
    ]


# ------------------------------------------------------- TLS fingerprinting
def parse_client_hello(blob: bytes) -> dict:
    """Minimal TLS ClientHello parser -> a JA3-style fingerprint.
    Returns {version, ciphers, ext_order, alpn, sni, supported_versions, ja3,
             ja3s_sha256, len}."""
    import hashlib
    d = blob
    if len(d) < 5 or d[0] != 0x16:
        return {"error": "not a TLS handshake record", "len": len(d)}
    rec_len = int.from_bytes(d[3:5], "big")
    d = d[5:5 + rec_len]
    if not d or d[0] != 0x01:
        return {"error": "not a ClientHello", "len": len(blob)}
    p = 4                                   # handshake type(1)+length(3)
    ver = "%d.%d" % (d[p], d[p + 1]); p += 2
    p += 32                                 # random
    sid_len = d[p]; p += 1 + sid_len
    cs_len = int.from_bytes(d[p:p + 2], "big"); p += 2
    ciphers = [int.from_bytes(d[p + i:p + i + 2], "big")
               for i in range(0, cs_len, 2)]
    p += cs_len
    comp_len = d[p]; p += 1 + comp_len
    ext_order, alpn, sni, sup = [], [], [], []
    if p < len(d):
        el = int.from_bytes(d[p:p + 2], "big"); p += 2
        end = p + el
        gre = []
        while p + 4 <= end:
            et = int.from_bytes(d[p:p + 2], "big")
            elen = int.from_bytes(d[p + 2:p + 4], "big")
            body = d[p + 4:p + 4 + elen]
            ext_order.append(et)
            if et == 0:                      # server_name
                try:
                    nlen = int.from_bytes(body[5:7], "big")
                    sni.append(body[7:7 + nlen].decode("ascii", "replace"))
                except Exception:
                    pass
            elif et == 16 and len(body) >= 2:
                # ALPN: uint16 list-length, then uint8 len + name entries
                n = int.from_bytes(body[0:2], "big")
                j = 2
                while j < 2 + n and j < len(body):
                    ln = body[j]
                    alpn.append(body[j + 1:j + 1 + ln].decode("ascii", "replace"))
                    j += 1 + ln
            elif et == 43 and len(body) >= 1:
                n = body[0]; sup = ["0x%04x" % int.from_bytes(
                    body[1 + i:3 + i], "big") for i in range(0, n, 2)]
            elif et == 10:
                gre = ["0x%04x" % int.from_bytes(
                    body[i:i + 2], "big") for i in range(0, len(body) - 1, 2)]
            p += 4 + elen
    ja3 = "%s,%s,%s,%s,%s" % (
        ver, "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in ext_order),
        "-".join(gre) if gre else "", "-".join(str(x) for x in sup))
    return {"version": ver, "ciphers": ["0x%04x" % c for c in ciphers],
            "cipher_count": len(ciphers), "ext_order": ext_order,
            "alpn": alpn, "sni": sni, "supported_versions": sup,
            "grease": gre, "ja3": ja3,
            "ja3_md5": hashlib.md5(ja3.encode()).hexdigest(),
            "ja3_sha256": hashlib.sha256(ja3.encode()).hexdigest()[:32],
            "hello_len": len(blob)}


class HelloSniffer:
    """TCP listener that grabs exactly one ClientHello then closes."""

    def __init__(self, host="0.0.0.0", port=9443):
        import socket
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.captured = []
        import threading
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        while True:
            try:
                c, a = self.sock.accept()
            except Exception:
                return
            try:
                c.settimeout(4)
                data = b""
                while len(data) < 4096:
                    try:
                        b = c.recv(4096)
                    except Exception:
                        break
                    if not b:
                        break
                    data += b
                    if len(data) >= 5 and \
                       int.from_bytes(data[3:5], "big") + 5 <= len(data):
                        break
                self.captured.append({"peer": "%s:%d" % a, "raw": data,
                                      "hello": parse_client_hello(data)})
            finally:
                try:
                    c.close()
                except Exception:
                    pass

    def take(self, wait=8.0):
        import time as _t
        t0 = _t.time()
        while _t.time() - t0 < wait and not self.captured:
            _t.sleep(0.05)
        return self.captured[-1] if self.captured else None

    def clear(self):
        self.captured = []


def _probe_httpclient(sn, url="https://127.0.0.1:%d/"):
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        c = http.client.HTTPSConnection("127.0.0.1", sn.port, timeout=6,
                                        context=ctx)
        c.request("GET", "/", headers={"Host": "app.adjust.com"})
    except Exception:
        pass
    return sn.take()


def _probe_curl_cffi(sn, impersonate="chrome131_android"):
    from curl_cffi import requests as cr
    try:
        cr.get("https://127.0.0.1:%d/" % sn.port, impersonate=impersonate,
               timeout=6, verify=False)
    except Exception:
        pass
    return sn.take()


def _probe_tls_client(sn, identifier="okhttp4_android_12"):
    import tls_client
    try:
        s = tls_client.Session(client_identifier=identifier,
                               random_tls_extension_order=True)
        s.get("https://127.0.0.1:%d/" % sn.port, insecure_skip_verify=True,
              timeout_seconds=6, headers={"Host": "app.adjust.com"})
    except Exception as e:
        print("    (tls_client probe: %s)" % str(e)[:90])
    return sn.take()


def _probe_device_curl(sn):
    """The device's own curl, pointed at the sniffer over `adb reverse`
    (gives Android BoringSSL's ClientHello — the closest cheap proxy for the
    app's own OkHttp/Conscrypt stack)."""
    subprocess.run([ADB, "-s", DEVICE_SERIAL, "reverse",
                    "tcp:%d" % sn.port, "tcp:%d" % sn.port],
                   capture_output=True, timeout=30)
    script = "curl -s -k -m 8 https://127.0.0.1:%d/ >/dev/null 2>&1" % sn.port
    subprocess.run([ADB, "-s", DEVICE_SERIAL, "shell", script],
                   capture_output=True, timeout=60)
    return sn.take(wait=10)


def phase_tlsfp():
    """Compare the ClientHello each transport emits against the app's."""
    sn = HelloSniffer()
    probes = [
        ("A  http.client (CPython/OpenSSL)", lambda: _probe_httpclient(sn)),
        ("B  curl_cffi chrome131_android",
         lambda: _probe_curl_cffi(sn, "chrome131_android")),
        ("B2 curl_cffi chrome99_android",
         lambda: _probe_curl_cffi(sn, "chrome99_android")),
        ("B3 curl_cffi chrome131 (desktop)",
         lambda: _probe_curl_cffi(sn, "chrome131")),
        ("C  tls_client okhttp4_android_12",
         lambda: _probe_tls_client(sn, "okhttp4_android_12")),
        ("C2 tls_client okhttp4_android_13",
         lambda: _probe_tls_client(sn, "okhttp4_android_13")),
        ("D  device curl (Android BoringSSL)", lambda: _probe_device_curl(sn)),
    ]
    out = []
    print("\n### ClientHello fingerprints (sniffer on 127.0.0.1:%d)\n" % sn.port)
    print("%-38s %-7s %-6s %-4s %-9s %s" %
          ("transport", "ver", "ciph", "ext", "alpn", "ja3 sha256[:16]"))
    for name, fn in probes:
        sn.clear()
        try:
            cap = fn()
        except Exception as e:
            cap = None
            print(name, "probe failed:", e)
        if not cap:
            print("%-38s  (no ClientHello captured)" % name)
            out.append({"transport": name, "captured": False})
            continue
        h = cap["hello"]
        if "error" in h:
            print("%-38s  parse: %s" % (name, h["error"]))
            out.append({"transport": name, "captured": True, **h})
            continue
        print("%-38s %-7s %-6d %-4d %-9s %s" %
              (name, h["version"], h["cipher_count"], len(h["ext_order"]),
               ",".join(h["alpn"]) or "-", h["ja3_sha256"][:16]))
        print("%-38s ciphers %s" % ("", " ".join(h["ciphers"])))
        print("%-38s ext     %s" % ("", h["ext_order"]))
        print("%-38s tls1.3  %s" % ("", ",".join(h["supported_versions"]) or "-"))
        out.append({"transport": name, "captured": True, **h})
        time.sleep(0.4)
    os.makedirs(OUTDIR, exist_ok=True)
    p = os.path.join(OUTDIR, "tls_fingerprints.json")
    json.dump(out, open(p, "w"), indent=1)
    print("\nsaved", p)
    return out


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "all"
    rows = parse_capture()
    if phase == "tlsfp":
        phase_tlsfp()
        return 0
    if phase == "paired":
        order = tuple((sys.argv[2] if len(sys.argv) > 2
                       else "A,D,E,B,C,FLIP").split(","))
        paired_session(order, outfile=os.path.join(OUTDIR,
                                                  "paired_results.json"))
        return 0
    if phase == "extract":
        for r in rows:
            b = base64.b64decode(r["blob_b64"]) if r["blob_b64"] else b""
            print("row %d %-12s gps=%s uuid=%s created=%s blob=%dB" % (
                r["row"], r["kind"], r["gps_adid"], r["android_uuid"],
                r["created_at"], len(b)))
        return 0

    sess = pick(rows, "session")
    attr = pick(rows, "attribution")
    print("session     row %d  gps=%s  created=%s" % (
        sess["row"], sess["gps_adid"], sess["created_at"]))
    print("attribution row %d  gps=%s  created=%s" % (
        attr["row"], attr["gps_adid"], attr["created_at"]))

    if phase in ("attr", "all"):
        q = wire_query(attr["claims"], attr["order"])
        os.makedirs(OUTDIR, exist_ok=True)
        open(os.path.join(OUTDIR, "attr_query.txt"), "w").write(q)
        print("\n### GET /attribution  %d params, %d query bytes, blob %d B\n" % (
            len([k for k in attr["order"]
                 if k in attr["claims"] and k not in CANON_ONLY]),
            len(q), len(base64.b64decode(attr["blob_b64"]))))
        run_plan(standard_plan(attr["blob_b64"]), "GET", "/attribution?" + q,
                 None, os.path.join(OUTDIR, "attr_results.json"))

    if phase in ("session", "all"):
        order = [k for k in SESSION_WIRE_ORDER if k in sess["claims"]]
        order += [k for k in sess["order"]
                  if k in sess["claims"] and k not in order]
        body = wire_query(sess["claims"], order)
        open(os.path.join(OUTDIR, "session_body.txt"), "w").write(body)
        print("\n### POST /session  %d params, %d body bytes, blob %d B\n" % (
            len([k for k in order if k not in CANON_ONLY]), len(body),
            len(base64.b64decode(sess["blob_b64"]))))
        run_plan(standard_plan(sess["blob_b64"]), "POST", "/session", body,
                 os.path.join(OUTDIR, "session_results.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
