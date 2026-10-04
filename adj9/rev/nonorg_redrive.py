r"""nonorg_redrive.py — re-drive the GENUINE non-organic record with OUR signature.

The user's test, run literally: take the one install in the whole corpus that
earned non-organic (saz _saz_x/raw/{1,2}_c.txt, GAID d016e7e4, tracker
24pxw9rl / VKM Digital Yeni, response 3_s.txt = tracker_token 24pxw9rl) and
replay those exact wire params -- but signed by OUR signer instead of the
device's -- then poll /attribution and see what comes back.

If OUR signature is missing something, the replay goes Organic where the
original was non-organic.

TWO GAID MODES, because they answer different questions:
  SAME  = replay on the original GAID d016e7e4.  Attribution there is already
          stored and immutable (is_reattributed=false), so a non-organic reply
          proves nothing about our signature -- it is just the stored record.
          Reported anyway, for completeness.
  FRESH = replay the identical click/referrer/timings on a brand-new GAID.  This
          is the real test: nothing is stored, so whatever comes back is
          caused purely by what we send.

d016e7e4 is a saz test device, NOT the connected device (f476b3d4 / ZD2228MY3X),
which is never touched.
"""
from __future__ import annotations
import base64, gzip, http.client, json, os, re, struct, sys, time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M
import F as Fmod

SAZ = os.path.join(HERE, "_saz_x", "raw")
OUT = os.path.join(HERE, "nonorg_redrive_result.json")
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
ADJ_V = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
REAL_GAID = "d016e7e4-fb1c-4d0a-b619-db01f6a6a262"
REAL_AUID = "073ccff9-c71c-4987-a914-167666ff7c26"


def req(method, path, params, auth):
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        if method == "POST":
            body = urllib.parse.urlencode(params).encode()
            c.putrequest("POST", path, skip_host=1, skip_accept_encoding=1)
            c.putheader("Client-SDK", "android5.7.0")
            c.putheader("Authorization", auth)
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.putheader("User-Agent", UA); c.putheader("Host", "app.adjust.com")
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
            c.putheader("User-Agent", UA); c.putheader("Host", "app.adjust.com")
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


def load(fn):
    t = open(os.path.join(SAZ, fn), encoding="utf-8", errors="replace").read()
    body = t.split("\n\n", 1)[1]
    return dict(urllib.parse.parse_qsl(body.strip(), keep_blank_values=True))


def mint(params, kind, sec):
    claims = dict(params)
    for k, v in (("adj_verification", ADJ_V), ("adj_signing_id", "1500000"),
                 ("headers_id", "10"), ("native_version", "5.0.0"),
                 ("activity_kind", kind), ("client_sdk", "android5.7.0")):
        claims.setdefault(k, v)
    padded, unpadded = M.claims_for_law(claims, kind)
    d0w, d2w, d4w = Fmod.region(sec, M.DEFAULT_PID, 0, head=M.DEVICE_SELECTORS)
    by = {0: (36, 0, b"".join(struct.pack(">I", w) for w in d0w)),
          9: (5, 0, bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")),
          8: (4, 0, bytes.fromhex("bffffffffffffd1f0007000000000000")),
          4: (8, 0, b"".join(struct.pack(">I", w) for w in d4w)),
          2: (1, 0, d2w.to_bytes(4, "big")),
          7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    blob, info = M.finex_mint([by[i] for i in M.VA_ORDER], sec)
    return blob, info


def auth_of(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_V))


def rebase(p, gps, auid, shift):
    """Keep every genuine field, swap identity, shift timestamps by `shift`.

    Timestamps come in two shapes: with milliseconds (created_at, installed_at)
    and whole seconds (click_time, install_begin_time, *_server).  Both must be
    re-formatted in their original precision and keep the original UTC offset.
    """
    import datetime as dt
    out = dict(p)
    out["gps_adid"] = gps
    out["android_uuid"] = auid
    for k in ("created_at", "sent_at", "installed_at", "updated_at",
              "click_time", "click_time_server", "install_begin_time",
              "install_begin_time_server"):
        if k not in out:
            continue
        v = urllib.parse.unquote(out[k])
        if "." in v:                      # millisecond precision
            d = dt.datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%fZ%z")
            new = d + dt.timedelta(seconds=shift)
            out[k] = new.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + v[-6:]
        else:                             # whole seconds
            d = dt.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ%z")
            new = d + dt.timedelta(seconds=shift)
            out[k] = new.strftime("%Y-%m-%dT%H:%M:%S") + "Z" + v[-5:]
    return out


def score(status, body):
    if status != 200:
        return "FAILURE (HTTP %d: %s)" % (status, body[:120])
    try:
        att = json.loads(body).get("attribution")
    except Exception:
        return "FAILURE (unparseable)"
    if not att:
        return "FAILURE (200, no attribution)"
    net, tok = att.get("network"), att.get("tracker_token")
    if net and net != "Organic":
        return "*** NON-ORGANIC: %s / %s ***" % (net, tok)
    return "ORGANIC (%s / %s)" % (net, tok)


def run(mode, gps, auid, shift):
    sp = rebase(load("1_c.txt"), gps, auid, shift)
    cp = rebase(load("2_c.txt"), gps, auid, shift)
    rec = {"mode": mode, "gps": gps, "session_keys": len(sp),
           "click_keys": len(cp),
           "referrer": cp.get("referrer")}
    sec = int(time.time())
    bs, isess = mint(sp, "session", sec)
    st, bd = req("POST", "/session", sp, auth_of(bs))
    rec["session"] = [st, bd[:200]]
    bc, iclick = mint(cp, "click", sec)
    stc, bdc = req("POST", "/sdk_click", cp, auth_of(bc))
    rec["sdk_click"] = [stc, bdc[:200]]
    for w in (10, 30, 75, 150):
        time.sleep(w)
        ap = {"app_token": "jut9tib0eeps", "gps_adid": gps,
              "android_uuid": auid, "initiated_by": "backend",
              "environment": "production", "needs_response_details": "1",
              "attribution_deeplink": "1", "created_at": sp["created_at"],
              "app_version": "3.13.9", "api_level": "31", "os_version": "12",
              "device_name": "moto g42", "device_type": "phone",
              "os_name": "android", "package_name": "com.penti.app",
              "gps_adid_src": "service", "tracking_enabled": "1",
              "foreground": "1", "gps_adid_attempt": "1",
              "offline_mode_enabled": "0", "ui_mode": "1"}
        ba, _ = mint(ap, "attribution", int(time.time()))
        sa, bda = req("GET", "/attribution", ap, auth_of(ba))
        rec["verdict"] = score(sa, bda)
        rec["last"] = [sa, bda[:300]]
        print("   %s +%ds: %s" % (mode, w, rec["verdict"]), flush=True)
        if "NON-ORGANIC" in rec["verdict"]:
            break
    return rec


def main():
    import uuid
    out = []
    # SAME GAID: the stored attribution is immutable, so this is informational.
    print("=== SAME (original GAID %s) ===" % REAL_GAID, flush=True)
    r1 = run("SAME", REAL_GAID, REAL_AUID, 0)
    out.append(r1)
    # FRESH GAID: the real test.
    print("=== FRESH GAID, identical click/timings/referrer ===", flush=True)
    r2 = run("FRESH", str(uuid.uuid4()), str(uuid.uuid4()), 0)
    out.append(r2)
    json.dump(out, open(OUT, "w"), indent=1)
    print("\n=== VERDICT ===")
    for r in out:
        print("  %-6s gps=%s -> %s" % (r["mode"], r["gps"][:8], r["verdict"]))
    print("  (original device record was: network=VKM Digital Yeni, "
          "tracker=24pxw9rl)")
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
