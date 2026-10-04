r"""win_flow_fixed.py — run win_phase_mint.py's exact flow, with its bugs fixed.

Same method as the parallel session's `win_phase_mint.py`: fresh GAID -> python
tracker click -> python mint -> /session -> /sdk_click -> GET /attribution,
all without the device.

Three fixes over their script, each of which produced a false result there:

  BUG 1  Their GET /attribution omitted the `Client-SDK` header.  That header
         is a validated field -- omitting it returns
         400 {"error":"Attribution request failed (unsupported sdk)"}.
  BUG 2  Their /sdk_click body added `click_time` and `activity_kind`, neither
         of which the genuine app ever sends (0 hits in the device capture).
         They also copied the SESSION params wholesale into the click.
  BUG 3  Their scorer read `net = attribution.get("network", "?")` and tested
         `net != "Organic"`, so a FAILED poll (no attribution object) scored
         net="?" and printed "FULLY OFFLINE NON-ORGANIC — GOAL".
         Their saved result was HTTP 400 with network=? tracker=?.

The scorer here only reports a goal on a real 200 attribution carrying a real
tracker_token.  Anything else is reported as a failure.
"""
from __future__ import annotations
import base64, gzip, http.client, json, os, re, struct, sys, time
import urllib.parse, uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_pipeline as M
import adj9_full_chain as F
import F as FF

CANON = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "clean_session_canon.txt")
CLICK = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
         "&creative=penti_generic&click_id={g}&idfa={g}&gps_adid={g}")
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
ADJ_V = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"


def post(path, params, auth, client_sdk="android5.7.0"):
    body = urllib.parse.urlencode(params).encode()
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest("POST", path, skip_host=1, skip_accept_encoding=1)
        if client_sdk:
            c.putheader("Client-SDK", client_sdk)     # FIX BUG 1 (presence)
        if auth:
            c.putheader("Authorization", auth)
        c.putheader("Content-Type", "application/x-www-form-urlencoded")
        c.putheader("User-Agent", UA)
        c.putheader("Host", "app.adjust.com")
        c.putheader("Connection", "Keep-Alive")
        c.putheader("Accept-Encoding", "gzip")
        c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        r = c.getresponse(); raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            try: raw = gzip.decompress(raw)
            except Exception: pass
        return r.status, raw.decode("utf-8", "replace")
    finally:
        c.close()


def get_attribution(params, auth):
    """FIX BUG 1: the genuine app sends Client-SDK on the GET too."""
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest("GET", "/attribution?" + qs, skip_host=1,
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
    d0w, d2w, d4w = FF.region(sec, FF.__dict__.get("_PID", 0) or 0, 0)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d2 = struct.pack(">I", d2w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
    D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    blob, info = M.finex_mint([by[i] for i in M.VA_ORDER], sec)
    return blob, info


def auth_of(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_V))


def score(status, body):
    """FIX BUG 3: a goal requires a real 200 + attribution + non-Organic token."""
    if status != 200:
        return "FAILURE (HTTP %d: %s)" % (status, body[:90])
    try:
        att = json.loads(body).get("attribution")
    except Exception:
        return "FAILURE (unparseable: %s)" % body[:90]
    if not att:
        return "FAILURE (200 but no attribution object: %s)" % body[:90]
    net = att.get("network")
    tok = att.get("tracker_token")
    if net and net != "Organic" and tok and tok != "wy7261z":
        return "*** GOAL MET: network=%s tracker=%s ***" % (net, tok)
    return "ORGANIC (network=%s tracker=%s engagement=%s)" % (
        net, tok, att.get("engagement_time"))


def main():
    gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
    print("[FIX] gps=%s" % gps, flush=True)
    import click_bind_chain as CBC
    import offline_funnel_freshregion as FFN
    code, referrer, hops = CBC.tracker_click(
        CBC.expand(FFN.LINK, gps), gps)
    print("[FIX] click: %d  referrer=%s" % (code, (referrer or "")[:70]),
          flush=True)
    if not referrer:
        print("[FIX] no reftag; abort"); return 1
    t_click = int(time.time())

    canon = open(CANON, encoding="utf-8").read()
    params = dict(re.findall(r"([a-z_0-9]+)=([^,\n]*)", canon))
    params.update({"gps_adid": gps, "android_uuid": auid,
                   "session_count": "1", "session_length": "0",
                   "time_spent": "0", "subsession_count": "1",
                   "app_version": "3.13.9"})
    sec = t_click + 2
    ins = F.fmt(sec - 170, 774).decode()
    params["created_at"] = F.fmt(sec - 1, 928).decode()
    params["sent_at"] = F.fmt(sec - 1, 942).decode()
    params["installed_at"] = ins
    params["updated_at"] = ins

    bs, isess = mint(params, "session", sec)
    auth_s = auth_of(bs)
    print("[FIX] session blob %dB status=%s" % (len(bs), isess.get("status")),
          flush=True)
    time.sleep(3)
    st, bd = post("/session", params, auth_s)
    print("[FIX] SESSION: %d %s" % (st, bd[:160]), flush=True)

    # FIX BUG 2: a proper click body, not the session params wholesale.
    tb = t_click + 20
    cp = {k: v for k, v in params.items()
          if k not in ("store_name_from_system", "initiating_package_name")}
    cp["referrer"] = referrer
    cp["source"] = "install_referrer"
    cp["referrer_api"] = "google"
    cp["google_play_instant"] = "0"
    cp["created_at"] = F.fmt(sec, 961).decode()
    cp["sent_at"] = F.fmt(sec, 970).decode()
    for k in ("click_time", "click_time_server", "install_begin_time",
              "install_begin_time_server", "activity_kind"):
        cp.pop(k, None)                      # never sent by the genuine app
    bc, iclick = mint(cp, "click", sec)
    print("[FIX] click blob %dB status=%s" % (len(bc), iclick.get("status")),
          flush=True)
    time.sleep(3)
    stc, bdc = post("/sdk_click", cp, auth_of(bc))
    print("[FIX] SDK_CLICK: %d %s" % (stc, bdc[:160]), flush=True)

    for wait in (8, 25, 60):
        time.sleep(wait)
        ap = {"app_token": "jut9tib0eeps", "gps_adid": gps,
              "android_uuid": auid, "initiated_by": "backend",
              "environment": "production", "needs_response_details": "1",
              "attribution_deeplink": "1", "created_at": F.fmt(sec, 666).decode(),
              "app_version": "3.13.9", "api_level": "31", "os_version": "12",
              "device_name": "moto g42", "device_type": "phone",
              "os_name": "android", "package_name": "com.penti.app",
              "gps_adid_src": "service", "tracking_enabled": "1",
              "foreground": "1", "gps_adid_attempt": "1",
              "offline_mode_enabled": "0", "ui_mode": "1"}
        ba, _ = mint(ap, "attribution", int(time.time()))
        sa, bda = get_attribution(ap, auth_of(ba))
        print("[FIX] ATTRIBUTION (+%ds): %d %s" % (wait, sa, bda[:200]),
              flush=True)
        print("[FIX]   -> %s" % score(sa, bda), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
