#!/usr/bin/env python3
r"""transport_fingerprint_test.py — does the HTTP TRANSPORT decide whether
app.adjust.com recognises a known-good adj9 signature blob?

Sources of truth
  transport_session.json : 43-key /session params + the full Authorization
                           header (captured genuine 192-B blob) + blob hex.
  transport_identity.json: the identity the task pins (363e5b78...).

Everything is held CONSTANT except the transport: same params, same blob, same
header set, same PC, same minute.  Any verdict difference is therefore a
transport effect and nothing else.

Headers (identical for every transport, per spec)
  Authorization:      <auth string verbatim from transport_session.json>
  Client-SDK:         android5.7.0
  User-Agent:         Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)
  Content-Type:       application/x-www-form-urlencoded   (POST only)
  Host:               app.adjust.com
  Connection:         Keep-Alive
  Accept-Encoding:    gzip

Arms
  A      python stdlib http.client.HTTPSConnection      (baseline, CPython/OpenSSL)
  B      curl_cffi impersonate=chrome131                 (+ chrome124, chrome119)
  C      tls_client okhttp4_android_11  (+ chrome_120)   (needs pip install tls-client)
  D      device curl via adb shell                      (CONTROL: phone's own
                                                        BoringSSL stack + phone IP)
  FLIP   genuine params, blob byte0 bit0 flipped        (CONTROL: MUST not pass)
  NOAUTH no Authorization header at all                 (CONTROL: MUST not pass)

Verdict
  PASS   response JSON contains "ask_in"
         or HTTP 400 "too frequent session" (record exists server-side)
         or attribution is non-Organic
  FAIL   HTTP 200 with tracker_name=Organic + engagement_time 0001-01-01T00:00:00Z

Usage
  python transport_fingerprint_test.py attr        # GET /attribution  (sharp, ungated)
  python transport_fingerprint_test.py session     # POST /session
  python transport_fingerprint_test.py all
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.path.join(HERE, "transport")
SESSJSON = os.path.join(HERE, "transport_session.json")
IDJSON = os.path.join(HERE, "transport_identity.json")
sys.stdout.reconfigure(line_buffering=True)

HOST = "app.adjust.com"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)"
CLIENT_SDK = "android5.7.0"
SERIAL = os.environ.get("ANDROID_SERIAL", "ZD2228MY3X")
ADB = os.environ.get("ADB", "adb")

# keys that live in the Authorization header, never in the body
CANON_ONLY = {"activity_kind", "client_sdk", "adj_verification", "headers_id",
              "adj_signing_id", "native_version", "algorithm"}


def load():
    s = json.load(open(SESSJSON, encoding="utf-8"))
    try:
        ident = json.load(open(IDJSON, encoding="utf-8"))
    except Exception:
        ident = {}
    return s, ident


def capture_attribution(gps):
    """The app's REAL /attribution param set + its genuine blob, lifted from
    transport_capture_log.txt.  The 3-param query the task sketches returns
    404 'failed to get app token' for every transport (no app_token key), so it
    carries no recognition signal at all — the full app param set is required."""
    sys.path.insert(0, HERE)
    import transport_test as tt
    rows = tt.parse_capture()
    for r in rows:
        if r["kind"] == "attribution" and r["gps_adid"] == gps:
            return r
    for r in rows:
        if r["kind"] == "attribution":
            return r
    raise SystemExit("no attribution row in capture")


# --------------------------------------------------------------- header block
def build_headers(auth, body):
    """The EXACT header set the task pins, as an ordered list of (name, value)
    plus a dict (order is applied verbatim on the raw-socket arm)."""
    h = [("Client-SDK", CLIENT_SDK),
         ("User-Agent", UA),
         ("Content-Type", "application/x-www-form-urlencoded"),
         ("Host", HOST),
         ("Connection", "Keep-Alive"),
         ("Accept-Encoding", "gzip")]
    if auth is not None:
        # Authorization goes FIRST, exactly as the app sends it
        h.insert(0, ("Authorization", auth))
    if body is not None:
        h.append(("Content-Length", str(len(body.encode()))))
    return h


def _decompress(raw, enc):
    if enc and "gzip" in enc.lower():
        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    return raw


# ----------------------------------------------------------------- transports
def send_httpclient(method, path, auth, body):
    """Arm A — CPython stdlib. putrequest/putheader keeps our header order and
    suppresses the automatic Host + Accept-Encoding that would otherwise
    duplicate/override ours."""
    t0 = time.time()
    c = http.client.HTTPSConnection(HOST, timeout=45)
    c.putrequest(method, path, skip_host=1, skip_accept_encoding=1)
    for k, v in build_headers(auth, body):
        c.putheader(k, v)
    c.endheaders(body.encode() if body is not None else None)
    r = c.getresponse()
    raw = r.read()
    enc = r.getheader("Content-Encoding")
    txt = _decompress(raw, enc).decode("utf-8", "replace")
    st = r.status
    c.close()
    return st, txt, time.time() - t0, enc or "-"


def send_curl_cffi(method, path, auth, body, impersonate="chrome131"):
    from curl_cffi import requests as cr
    t0 = time.time()
    hdrs = [(k, v) for k, v in build_headers(auth, body)
            if k not in ("Host", "Content-Length")]
    url = "https://%s%s" % (HOST, path)
    kw = dict(headers=dict(hdrs), impersonate=impersonate, timeout=45)
    if method == "POST":
        r = cr.post(url, content=body.encode(), **kw)
    else:
        r = cr.get(url, **kw)
    return (r.status_code, r.text, time.time() - t0,
            r.headers.get("Content-Encoding", "-") or "-")


def send_tls_client(method, path, auth, body, identifier="okhttp4_android_11"):
    import tls_client
    t0 = time.time()
    s = tls_client.Session(client_identifier=identifier,
                           random_tls_extension_order=True)
    hdrs = [(k, v) for k, v in build_headers(auth, body)
            if k not in ("Host", "Content-Length")]
    url = "https://%s%s" % (HOST, path)
    r = s.post(url, headers=dict(hdrs), data=body.encode()) if method == "POST" \
        else s.get(url, headers=dict(hdrs))
    return (r.status_code, r.text, time.time() - t0,
            r.headers.get("content-encoding", "-") or "-")


def send_device_curl(method, path, auth, body):
    """Arm D — the CONTROL. The request leaves from the phone: its IP, its
    BoringSSL, its network path.  The script is pushed to the device so no
    host-side shell quoting can mangle the header values."""
    t0 = time.time()
    parts = ["curl", "-sS", "-k", "--compressed", "--max-time", "60",
             "-X", method, "-w", "'\\n###HTTP:%{http_code}'"]
    for k, v in build_headers(auth, body):
        if k in ("Host", "Content-Length"):
            continue
        parts += ["-H", "'%s: %s'" % (k, v)]
    if body is not None:
        parts += ["--data-raw", "'" + body + "'"]
    parts += ["'https://%s%s'" % (HOST, path)]
    script = " ".join(parts)
    os.makedirs(OUTDIR, exist_ok=True)
    tmp = os.path.join(OUTDIR, "_fp.sh")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(script + "\n")
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    subprocess.run([ADB, "-s", SERIAL, "push", tmp, "/data/local/tmp/fp.sh"],
                   env=env, capture_output=True, text=True, timeout=90)
    out = subprocess.run([ADB, "-s", SERIAL, "shell", "sh /data/local/tmp/fp.sh"],
                         capture_output=True, text=True, timeout=150)
    txt = out.stdout + (("\n[stderr] " + out.stderr.strip()) if out.stderr.strip() else "")
    m = re.search(r"###HTTP:(\d{3})", txt)
    st = int(m.group(1)) if m else 0
    b = (txt[:m.start()] if m else txt).strip()
    if b.startswith("{"):
        b = b[:b.rindex("}") + 1]
    return st, b, time.time() - t0, "gzip(--compressed)"


ARMS = [
    ("A",     "python http.client (CPython/OpenSSL)", send_httpclient, {}),
    ("B",     "curl_cffi chrome131",      lambda m,p,a,b: send_curl_cffi(m,p,a,b,"chrome131"), {}),
    ("B2",    "curl_cffi chrome124",      lambda m,p,a,b: send_curl_cffi(m,p,a,b,"chrome124"), {}),
    ("B3",    "curl_cffi chrome119",      lambda m,p,a,b: send_curl_cffi(m,p,a,b,"chrome119"), {}),
    ("C",     "tls_client okhttp4_android_11", lambda m,p,a,b: send_tls_client(m,p,a,b,"okhttp4_android_11"), {}),
    ("C2",    "tls_client chrome_120",    lambda m,p,a,b: send_tls_client(m,p,a,b,"chrome_120"), {}),
    ("D",     "DEVICE curl (BoringSSL, phone IP)", send_device_curl, {}),
]


# ------------------------------------------------------------------- judging
def classify(status, body):
    """-> (verdict, key_response_field)"""
    j = None
    try:
        j = json.loads(body)
    except Exception:
        pass
    if j is None:
        return "OTHER", body[:150].replace("\n", " ")
    if "ask_in" in j:
        return "PASS(ask_in)", "ask_in=%s adid=%s" % (j["ask_in"], j.get("adid", "?"))
    if "attribution" in j:
        a = j["attribution"]
        org = (a.get("tracker_name") == "Organic"
               and str(a.get("engagement_time", "")).startswith("0001-01-01"))
        key = ("tracker=%s network=%s eng=%s"
               % (a.get("tracker_token"), a.get("network"),
                  str(a.get("engagement_time"))[:19]))
        return ("FAIL(Organic)" if org else "PASS(non-organic)"), key
    if "error" in j:
        e = str(j["error"])
        if "too frequent" in e or "check interval" in e:
            m = re.search(r"interval: (\S+?), min interval", e)
            return "PASS(400 too-frequent/record-exists)", \
                   "gate hit, gap=%s min=20m" % (m.group(1) if m else "?")
        if "signature" in e.lower():
            return "FAIL(sig-reject)", e[:150]
        return "GATE(err)", e[:150]
    if "adid" in j:
        return "RESP", body[:150]
    return "OTHER", body[:150]


def body_hash(b):
    try:
        j = json.loads(b)
        return hashlib.sha256(json.dumps(j, sort_keys=True).encode()).hexdigest()[:12]
    except Exception:
        return hashlib.sha256(b.encode()).hexdigest()[:12]


def run_suite(method, path, body, auth, flip_b64, outfile, only=None):
    os.makedirs(OUTDIR, exist_ok=True)
    plan = [(t, d, fn, kw, auth, "genuine blob")
            for t, d, fn, kw in ARMS if (only is None or t in only)]
    plan += [("FLIP", "CONTROL genuine params, blob byte0 bit0 flipped",
              send_httpclient, {}, flip_b64, "corrupted blob"),
             ("NOAUTH", "CONTROL no Authorization header at all",
              send_httpclient, {}, None, "no auth")]
    rows = []
    print("### %s %s   body=%dB blob=%dB" %
          (method, path, len(body or ""), len(base64.b64decode(auth_blob) if auth_blob else b"")))
    print("%-7s %-38s %-5s %-7s %-34s %s" %
          ("arm", "transport", "http", "enc", "verdict", "key field"))
    for tag, desc, fn, kw, a, kind in plan:
        t0 = time.time()
        try:
            st, txt, el, enc = fn(method, path, a, body, **kw)
            err = ""
        except Exception as e:
            st, txt, el, enc, err = 0, "%s: %s" % (type(e).__name__, e), 0.0, "-", str(e)[:120]
        v, key = classify(st, txt)
        rows.append({"arm": tag, "transport": desc, "kind": kind, "status": st,
                     "encoding": enc, "verdict": v, "key": key, "elapsed": round(el, 2),
                     "body_sha": body_hash(txt), "body_len": len(txt),
                     "body": txt[:1200], "error": err})
        print("%-7s %-38s %-5s %-7s %-34s %s" % (tag, desc[:38], st, enc[:7], v, key[:70]))
        time.sleep(4)
    json.dump(rows, open(outfile, "w"), indent=1)

    print("\n== VERDICT TABLE (%s %s) ==" % (method, path.split("?")[0]))
    print("%-7s %-38s %-5s %-34s %-13s %s" %
          ("arm", "transport", "http", "verdict", "body_sha", "key"))
    for r in rows:
        print("%-7s %-38s %-5s %-34s %-13s %s" %
              (r["arm"], r["transport"][:38], r["status"], r["verdict"],
               r["body_sha"], r["key"][:60]))
    gen = [r for r in rows if r["kind"] == "genuine blob"]
    passed = [r["arm"] for r in rows if r["verdict"].startswith("PASS")]
    ctrl = [r for r in rows if r["kind"] != "genuine blob"]
    print("\n  genuine arms: %d   identical bodies: %d distinct sha among %d"
          % (len(gen), len({r['body_sha'] for r in gen}), len(gen)))
    print("  PASSING ARMS: %s" % (passed or "NONE"))
    print("  CONTROLS    : %s" % ", ".join("%s=%s" % (r["arm"], r["verdict"]) for r in ctrl))
    if gen and all(r["body_sha"] == gen[0]["body_sha"] for r in gen):
        print("  >> ALL genuine transports returned a BYTE-IDENTICAL body "
              "(sha=%s) -> the endpoint response is transport-INDEPENDENT"
              % gen[0]["body_sha"])
    if ctrl and gen and ctrl[0]["body_sha"] == gen[0]["body_sha"]:
        print("  >> CONTROLS (corrupted blob / no auth) also BYTE-IDENTICAL to the "
              "genuine responses -> this endpoint is NOT gating on the signature")
    print("\nsaved", outfile)
    return rows


def flip_b64_of(blob_b64):
    flip = bytearray(base64.b64decode(blob_b64)); flip[0] ^= 1
    return base64.b64encode(bytes(flip)).decode()


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "all"
    only = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else None
    global auth_blob
    s, ident = load()
    auth = s["auth"]
    auth_blob = s["blob_hex"]
    gps = ident.get("gps")
    params = s["params"]

    # POST body: the urlencoded params, in the file's own insertion order
    order = [k for k in params if k not in CANON_ONLY]
    body = "&".join("%s=%s" % (urllib.parse.quote(k, safe=""),
                               urllib.parse.quote(str(params[k]), safe=""))
                    for k in order)
    flip = bytearray(base64.b64decode(auth_blob)); flip[0] ^= 1
    flip_b64 = base64.b64encode(bytes(flip)).decode()

    print("session params : %d keys, %d body bytes" % (len(order), len(body)))
    print("session gps    : %s  (identity file pins %s)" % (params.get("gps_adid"), gps))
    print("blob           : %d B, auth %d chars" % (len(auth_blob) // 2, len(auth)))
    print()

    if phase in ("attr", "all"):
        # (1) the app's REAL attribution param set, with the app's own blob
        ar = capture_attribution(gps)
        aorder = [k for k in ar["order"] if k in ar["claims"] and k not in CANON_ONLY]
        q = "&".join("%s=%s" % (urllib.parse.quote(k, safe=""),
                                urllib.parse.quote(str(ar["claims"][k]), safe=""))
                     for k in aorder)
        print("attribution param set: %d keys, %d query bytes, blob %d B (capture row %d)\n"
              % (len(aorder), len(q), len(base64.b64decode(ar["blob_b64"])), ar["row"]))
        run_suite("GET", "/attribution?" + q, None, ar["auth"],
                  flip_b64_of(ar["blob_b64"]),
                  os.path.join(OUTDIR, "fp_attr_full_results.json"), only)
        print()
        # (2) the 3-param query the task sketches — kept as a control
        q3 = ("gps_adid=%s&activity_kind=attribution&initiated_by=sdk"
              % urllib.parse.quote(gps or params["gps_adid"], safe=""))
        run_suite("GET", "/attribution?" + q3, None, auth, flip_b64,
                  os.path.join(OUTDIR, "fp_attr_3param_results.json"), only)

    if phase in ("session", "all"):
        open(os.path.join(OUTDIR, "fp_session_body.txt"), "w").write(body)
        run_suite("POST", "/session", body, auth, flip_b64,
                  os.path.join(OUTDIR, "fp_session_results.json"), only)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
