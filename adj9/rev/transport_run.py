#!/usr/bin/env python3
"""transport_run.py -- which HTTP transport gets the KNOWN-GOOD adj9 signature
blob recognized by app.adjust.com?

Holds everything constant (same params, same blob, same headers) and varies
ONLY the transport.  Two probes per transport:

  POST /session      -> recognized == response carries "ask_in"
                      -> 400 "Ignoring too frequent session" == record exists
                         (identity already booked) -- counted as EXISTS, not PASS,
                         because /session is NOT signature-gated (the FLIP and
                         NOAUTH controls land there too)
  GET  /attribution  -> the SHARP probe.  recognized == 400 ask_in:7200000
                      -> Organic == the server never accepted the signature

Usage:
  python transport_run.py attr                 # attribution battery (fast)
  python transport_run.py session A B C D      # paired session, 20m gate wait
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

SESSION_JSON = os.path.join(HERE, "transport_session.json")
CAPTURE = os.path.join(HERE, "transport_capture_log.txt")
OUTDIR = os.path.join(HERE, "transport")

HOST = "app.adjust.com"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)"
CLIENT_SDK = "android5.7.0"
SERIAL = os.environ.get("ANDROID_SERIAL", "ZD2228MY3X")
ADB = os.environ.get("ADB", "adb")
TARGET_GPS = "363e5b78-8670-4c50-8348-9f87c604111b"

CANON_ONLY = {"activity_kind", "client_sdk", "adj_verification", "headers_id",
              "adj_signing_id", "native_version", "algorithm"}

# ---------------------------------------------------------------- header set
# The app's own wire profile (from the genuine Fiddler SAZ), used for EVERY
# arm so the only variable is the TLS/HTTP stack underneath.
def base_headers(blob_auth, body=None):
    h = [("Client-SDK", CLIENT_SDK)]
    if blob_auth:
        h.append(("Authorization", blob_auth))
    if body is not None:
        h.append(("Content-Type", "application/x-www-form-urlencoded"))
    h.append(("User-Agent", UA))
    h.append(("Host", HOST))
    h.append(("Connection", "Keep-Alive"))
    h.append(("Accept-Encoding", "gzip"))
    if body is not None:
        h.append(("Content-Length", str(len(body.encode()))))
    return h


# ---------------------------------------------------------------- transports
def _hdrdict(pairs):
    return dict(pairs)


def send_httpclient(method, path, hdrs, body=None):
    t0 = time.time()
    c = http.client.HTTPSConnection(HOST, timeout=45)
    c.putrequest(method, path, skip_host=1, skip_accept_encoding=1)
    for k, v in hdrs:
        c.putheader(k, v)
    c.endheaders(body.encode() if body is not None else None)
    r = c.getresponse()
    data = r.read()
    c.close()
    if r.getheader("Content-Encoding") == "gzip":
        try:
            import gzip
            data = gzip.decompress(data)
        except Exception:
            pass
    return r.status, data.decode("utf-8", "replace"), time.time() - t0


def send_curl_cffi(method, path, hdrs, body=None, impersonate="chrome131"):
    from curl_cffi import requests as cr
    t0 = time.time()
    url = "https://%s%s" % (HOST, path)
    kw = dict(headers=_hdrdict(hdrs), impersonate=impersonate, timeout=45)
    if method == "POST":
        r = cr.post(url, content=body.encode(), **kw)
    else:
        r = cr.get(url, **kw)
    return r.status_code, r.text, time.time() - t0


def send_tls_client(method, path, hdrs, body=None, identifier="chrome_120"):
    import tls_client
    t0 = time.time()
    s = tls_client.Session(client_identifier=identifier,
                           random_tls_extension_order=True)
    url = "https://%s%s" % (HOST, path)
    if method == "POST":
        r = s.post(url, headers=_hdrdict(hdrs), data=body.encode())
    else:
        r = s.get(url, headers=_hdrdict(hdrs))
    return r.status_code, r.text, time.time() - t0


def send_device_curl(method, path, hdrs, body=None):
    """CONTROL: request leaves from the phone (its IP, BoringSSL/TLS stack)."""
    t0 = time.time()
    parts = ["curl", "-s", "-S", "-k", "--compressed", "--max-time", "60",
             "-X", method, "-w", "'\\n###HTTP:%{http_code}'"]
    for k, v in hdrs:
        if k.lower() in ("host", "content-length"):
            continue
        parts += ["-H", "'%s: %s'" % (k, v)]
    if body is not None:
        parts += ["--data-raw", "'" + body + "'"]
    parts += ["'https://" + HOST + path + "'"]
    script = " ".join(parts)
    os.makedirs(OUTDIR, exist_ok=True)
    tmp = os.path.join(OUTDIR, "_tr.sh")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(script + "\n")
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    subprocess.run([ADB, "-s", SERIAL, "push", tmp, "/data/local/tmp/tr.sh"],
                   env=env, capture_output=True, text=True, timeout=120)
    out = subprocess.run([ADB, "-s", SERIAL, "shell", "sh /data/local/tmp/tr.sh"],
                         capture_output=True, text=True, timeout=180)
    txt = out.stdout + (("\n[stderr]" + out.stderr) if out.stderr else "")
    m = re.search(r"###HTTP:(\d{3})", txt)
    status = int(m.group(1)) if m else 0
    payload = (txt[:m.start()] if m else txt).strip()
    if payload.startswith("{"):
        payload = payload[:payload.rindex("}") + 1]
    if not payload and out.stderr:
        payload = out.stderr.strip()[:300]
    return status, payload, time.time() - t0


ARMS = {
    # tag -> (label, callable, extra-arg)
    "A":    ("python http.client (CPython/OpenSSL)",
             lambda m, p, h, b: send_httpclient(m, p, h, b)),
    "B131": ("curl_cffi impersonate=chrome131",
             lambda m, p, h, b: send_curl_cffi(m, p, h, b, "chrome131")),
    "B131a": ("curl_cffi impersonate=chrome131_android",
              lambda m, p, h, b: send_curl_cffi(m, p, h, b, "chrome131_android")),
    "B124": ("curl_cffi impersonate=chrome124",
             lambda m, p, h, b: send_curl_cffi(m, p, h, b, "chrome124")),
    "B119": ("curl_cffi impersonate=chrome119",
             lambda m, p, h, b: send_curl_cffi(m, p, h, b, "chrome119")),
    "Cok11": ("tls_client okhttp4_android_11",
              lambda m, p, h, b: send_tls_client(m, p, h, b, "okhttp4_android_11")),
    "Cok12": ("tls_client okhttp4_android_12",
              lambda m, p, h, b: send_tls_client(m, p, h, b, "okhttp4_android_12")),
    "Cok13": ("tls_client okhttp4_android_13",
              lambda m, p, h, b: send_tls_client(m, p, h, b, "okhttp4_android_13")),
    "C120":  ("tls_client chrome_120",
              lambda m, p, h, b: send_tls_client(m, p, h, b, "chrome_120")),
    "D":     ("device curl (phone IP + BoringSSL)", send_device_curl),
    # X: the transport_session.json pairing -- the row-0 blob pasted onto a
    # DIFFERENT identity's claims (gps 7cc81be0).  Signature-inconsistent by
    # construction; its own gate window is free (last session 09-25).
    "XJSON": ("python http.client | transport_session.json pairing",
              lambda m, p, h, b: send_httpclient(m, p, h, b)),
    "XJSONa": ("curl_cffi chrome131 | transport_session.json pairing",
               lambda m, p, h, b: send_curl_cffi(m, p, h, b, "chrome131")),
}


# ---------------------------------------------------------------- payload
def load_session_json():
    d = json.load(open(SESSION_JSON, encoding="utf-8"))
    params = d["params"]
    body = "&".join(
        "%s=%s" % (urllib.parse.quote(k, safe=""),
                   urllib.parse.quote(params[k], safe=""))
        for k in params if k not in CANON_ONLY)
    return params, d["auth"], body


def capture_rows():
    txt = open(CAPTURE, encoding="utf-8", errors="replace").read()
    blocks = re.findall(
        r"###ADJ9_BEGIN type=sign_input[^\n]*\n(.*?)\n###ADJ9_END", txt, re.S)
    auths = re.findall(
        r"###ADJ9_BEGIN type=authorization_header[^\n]*\ntext: ([^\n]*)", txt)
    rows = []
    for i, b in enumerate(blocks):
        s, order = None, []
        for line in b.split("\n"):
            if line.startswith("map_toString="):
                s = line[len("map_toString="):].lstrip("{")
            elif line.startswith("map_order="):
                order = [p.split("\x01")[0] for p in
                         line[len("map_order="):].split("\x02") if "\x01" in p]
        claims = {}
        for item in s.split(", "):
            k, _, v = item.partition("=")
            claims[k] = v
        blob = None
        if i < len(auths):
            blob = re.search(r'signature="([^"]+)"', auths[i]).group(1)
        rows.append({"row": i, "kind": claims.get("activity_kind", "?"),
                     "gps_adid": claims.get("gps_adid"), "claims": claims,
                     "order": order or list(claims), "blob": blob,
                     "auth": auths[i] if i < len(auths) else None})
    return rows


def wire_query(claims, order):
    keys = [k for k in order if k in claims and k not in CANON_ONLY]
    seen, out = set(), []
    for k in keys:
        if k in seen:
            continue
        seen.add(k)
        out.append("%s=%s" % (urllib.parse.quote(k, safe=""),
                              urllib.parse.quote(claims[k], safe="")))
    return "&".join(out)


# ---------------------------------------------------------------- judging
def classify(status, body):
    try:
        j = json.loads(body)
    except Exception:
        return "OTHER", (body[:180].replace("\n", " ") or "<empty>")
    if "ask_in" in j:
        return "PASS(recognized)", "ask_in=%s adid=%s" % (j["ask_in"],
                                                        j.get("adid", "?"))
    if "attribution" in j:
        a = j["attribution"]
        org = (a.get("tracker_name") == "Organic" and
               str(a.get("engagement_time", "")).startswith("0001-01-01"))
        return ("FAIL(Organic)" if org else "PASS(non-organic)"), \
            "tracker=%s network=%s eng=%s" % (
                a.get("tracker_name"), a.get("network"),
                str(a.get("engagement_time"))[:19])
    if "error" in j:
        e = j["error"]
        if "too frequent" in e:
            m = re.search(r"interval: (\S+?), min interval", e)
            return "EXISTS(400 gated)", "too frequent, gap=%s min-interval=20m" % (
                m.group(1) if m else "?")
        if "signature" in e.lower():
            return "REJECT(sig)", e[:180]
        return "ERR", e[:180]
    if "adid" in j:
        return "RESP", body[:150]
    return "OTHER", body[:150].replace("\n", " ")


def fire(tag, method, path, auth, body, extra=None):
    label, fn = ARMS[tag]
    hdrs = base_headers(auth, body if method == "POST" else None)
    t0 = time.time()
    try:
        st, txt, el = fn(method, path, hdrs, body)
    except Exception as e:
        st, txt, el = 0, "%s: %s" % (type(e).__name__, e), time.time() - t0
    v, n = classify(st, txt)
    print("  %-6s %-5s %6.2fs  %-17s %s" % (tag, st, el, v, n[:88]), flush=True)
    return {"tag": tag, "label": label, "probe": method, "status": st,
            "verdict": v, "note": n, "body": txt[:1200]}


# ---------------------------------------------------------------- phases
def phase_attr():
    params, sjson_auth, sbody = load_session_json()
    rows = capture_rows()
    attr = [r for r in rows if r["kind"] == "attribution"
            and r["gps_adid"] == TARGET_GPS][0]
    sess = [r for r in rows if r["kind"] == "session"
            and r["gps_adid"] == TARGET_GPS][0]

    variants = [
        ("Q1", "/attribution?gps_adid=%s&activity_kind=attribution"
               "&initiated_by=sdk" % TARGET_GPS, sjson_auth,
         "task query + transport_session.json auth"),
        ("Q2", "/attribution?" + wire_query(attr["claims"], attr["order"]),
         attr["auth"], "KNOWN-GOOD: full genuine attribution query + its own "
                       "genuine blob (row %d)" % attr["row"]),
        ("Q3", "/attribution?" + wire_query(attr["claims"], attr["order"]),
         sess["auth"], "genuine attribution query + SESSION blob"),
    ]
    flip = bytearray(base64.b64decode(attr["blob"]))
    flip[0] ^= 1
    bad = attr["auth"].replace(attr["blob"],
                               base64.b64encode(bytes(flip)).decode())
    variants.append(("Q4", "/attribution?" + wire_query(attr["claims"], attr["order"]),
                     bad, "CONTROL genuine query + blob byte0 bit0 flipped"))
    variants.append(("Q5", "/attribution?" + wire_query(attr["claims"], attr["order"]),
                     None, "CONTROL genuine query, NO Authorization header"))

    results = []
    for vname, path, auth, desc in variants:
        print("\n== %s  %s\n   %s" % (vname, desc, path[:150]))
        rowsv = []
        for tag in ARMS:
            rowsv.append(fire(tag, "GET", path, auth, None))
            time.sleep(2.5)
        results.append({"variant": vname, "desc": desc, "path": path,
                        "auth_sha": (auth or "none")[:0] or "len=%d" % len(auth or ""),
                        "rows": rowsv})
        os.makedirs(OUTDIR, exist_ok=True)
        json.dump(results, open(os.path.join(OUTDIR, "attr_battery.json"), "w"),
                  indent=1)
    print("\n\n===== ATTRIBUTION BATTERY =====")
    print("%-5s %-9s %s" % ("var", "arm", "verdict / note"))
    for v in results:
        for r in v["rows"]:
            print("%-5s %-9s %-17s %s" % (v["variant"], r["tag"],
                                          r["verdict"], r["note"][:60]))
    return results


def phase_session(order):
    params, sjson_auth, sbody = load_session_json()
    rows = capture_rows()
    sess = [r for r in rows if r["kind"] == "session"
            and r["gps_adid"] == TARGET_GPS][0]
    body = wire_query(sess["claims"], sess["order"])
    auth = sess["auth"]
    flip = bytearray(base64.b64decode(sess["blob"]))
    flip[0] ^= 1
    flipauth = sess["auth"].replace(sess["blob"],
                                    base64.b64encode(bytes(flip)).decode())
    out = []
    for tag in order:
        if tag == "FLIP":
            a, d, b_ = flipauth, "CONTROL: genuine params, blob byte0 bit0 flipped", body
        elif tag == "NOAUTH":
            a, d, b_ = None, "CONTROL: genuine params, no Authorization header", body
        elif tag.startswith("XJSON"):
            a, d, b_ = sjson_auth, ("transport_session.json pairing "
                                    "(row-0 blob on identity 7cc81be0)"), sbody
        else:
            a, d, b_ = auth, "genuine blob | %s" % ARMS[tag][0], body
        print("\n== %s  %s  (%d body bytes, blob %d B)"
              % (tag, d, len(b_), len(base64.b64decode(sess["blob"]))),
              flush=True)
        waited, shot = 0.0, None
        while True:
            shot = fire(tag, "POST", "/session", a, b_)
            shot["waited_s"] = round(waited, 1)
            if not shot["verdict"].startswith("EXISTS") or waited > 26 * 60:
                break
            print("    gated -> sleeping 120s for the 20m min-interval gate",
                  flush=True)
            time.sleep(120)
            waited += 120
        shot["desc"] = d
        shot["gps_adid"] = sess["gps_adid"]
        out.append(shot)
        os.makedirs(OUTDIR, exist_ok=True)
        json.dump(out, open(os.path.join(OUTDIR, "session_battery.json"), "w"),
                  indent=1)
        time.sleep(3)
    print("\n\n===== SESSION BATTERY =====")
    for r in out:
        print("  %-7s %-5s %-18s waited=%-6s %s"
              % (r["tag"], r["status"], r["verdict"], r.get("waited_s"),
                 r["note"][:60]))
    return out


if __name__ == "__main__":
    ph = sys.argv[1] if len(sys.argv) > 1 else "attr"
    if ph == "attr":
        phase_attr()
    elif ph == "session":
        phase_session(sys.argv[2].split(",") if len(sys.argv) > 2
                      else ["A", "D", "B131", "Cok12"])
    else:
        print(__doc__)
