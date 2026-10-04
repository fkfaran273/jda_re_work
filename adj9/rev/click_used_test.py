r"""click_used_test.py — does the server use the click at all?

Every run so far ends Organic, so "Organic" tells us nothing on its own.  The
discriminating question is what a NO-CLICK install looks like compared to one
that had a real tracker click.  If the two attribution payloads are identical
field-for-field, the server is not using the click we send, and no amount of
fixing the request will change the join.

Arms (each on its own fresh GAID, device untouched):
  N0  session only, NO tracker click, NO /sdk_click   <- the baseline
  N1  tracker click + session + /sdk_click            <- what we always do
  N2  tracker click + session, NO /sdk_click          <- click registered, never reported

All three then poll /attribution identically and we diff the attribution
objects field by field.  A real join shows up as tracker_token/network/
engagement_time/installed_at differing between N0 and N1.
"""
from __future__ import annotations
import base64, gzip, http.client, json, os, re, struct, sys, time, urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M
import adj9_full_chain as F
import F as FF
import click_bind_chain as CBC
import offline_funnel_freshregion as FFN

UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
ADJ_V = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
CANON = os.path.join(HERE, "clean_session_canon.txt")
OUT = os.path.join(HERE, "click_used_result.json")
POLL = (10, 30, 75)


def _req(method, path, params, auth, ua=UA):
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        if method == "POST":
            body = urllib.parse.urlencode(params).encode()
            c.putrequest("POST", path, skip_host=1, skip_accept_encoding=1)
            c.putheader("Client-SDK", "android5.7.0")
            c.putheader("Authorization", auth)
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.putheader("User-Agent", ua)
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
            c.putheader("User-Agent", ua)
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
    d0w, d2w, d4w = FF.region(sec, 0, 0, head=M.DEVICE_SELECTORS)
    D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
    D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
    by = {0: (36, 0, b"".join(struct.pack(">I", w) for w in d0w)),
          9: (5, 0, D9), 8: (4, 0, D8),
          4: (8, 0, b"".join(struct.pack(">I", w) for w in d4w)),
          2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    blob, info = M.finex_mint([by[i] for i in M.VA_ORDER], sec)
    return blob


def auth_of(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_V))


def session_params(gps, auid, sec):
    p = dict(re.findall(r"([a-z_0-9]+)=([^,\n]*)",
                        open(CANON, encoding="utf-8").read()))
    p.update({"gps_adid": gps, "android_uuid": auid, "session_count": "1",
              "session_length": "0", "time_spent": "0", "subsession_count": "1",
              "app_version": "3.13.9"})
    ins = F.fmt(sec - 170, 774).decode()
    p["created_at"] = F.fmt(sec - 1, 928).decode()
    p["sent_at"] = F.fmt(sec - 1, 942).decode()
    p["installed_at"] = ins; p["updated_at"] = ins
    return p


def run_arm(tag, do_click, do_sdkclick):
    gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
    rec = {"arm": tag, "gps": gps, "click": False, "sdk_click": False}
    referrer = None
    if do_click:
        code, referrer, _ = CBC.tracker_click(CBC.expand(FFN.LINK, gps), gps)
        rec["click"] = {"http": code,
                        "referrer": (referrer or "")[:120]}
        if not referrer:
            rec["verdict"] = "NO_REFTAG"; return rec
    sec = int(time.time()) + 2
    p = session_params(gps, auid, sec)
    st, bd = _req("POST", "/session", p, auth_of(mint(p, "session", sec)))
    rec["session"] = [st, bd[:200]]
    if do_sdkclick and referrer:
        cp = {k: v for k, v in p.items()
              if k not in ("store_name_from_system",
                           "initiating_package_name")}
        cp.update({"referrer": referrer, "source": "install_referrer",
                   "referrer_api": "google", "google_play_instant": "0",
                   "created_at": F.fmt(sec, 961).decode(),
                   "sent_at": F.fmt(sec, 970).decode()})
        stc, bdc = _req("POST", "/sdk_click", cp,
                        auth_of(mint(cp, "click", sec)))
        rec["sdk_click"] = [stc, bdc[:200]]
    atts = []
    for i, w in enumerate(POLL):
        time.sleep(w)
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
        sa, bda = _req("GET", "/attribution", ap,
                       auth_of(mint(ap, "attribution", int(time.time()))))
        try: a = json.loads(bda).get("attribution")
        except Exception: a = None
        atts.append({"http": sa, "attribution": a, "raw": bda[:300]})
        if a: break
    rec["polls"] = atts
    last = atts[-1].get("attribution") if atts else None
    rec["final"] = last
    rec["verdict"] = ("NO_ATTRIBUTION" if not last else
                      "%s / %s / eng=%s" % (last.get("network"),
                                            last.get("tracker_token"),
                                            last.get("engagement_time")))
    return rec


def main():
    arms = [("N0", False, False), ("N1", True, True), ("N2", True, False)]
    out = []
    for tag, dc, dsc in arms:
        print("=== %s  click=%s sdk_click=%s ===" % (tag, dc, dsc), flush=True)
        r = run_arm(tag, dc, dsc)
        print("   session=%s  verdict=%s" % (
            (r.get("session") or [None])[0], r["verdict"]), flush=True)
        out.append(r)
        json.dump(out, open(OUT, "w"), indent=1)

    print("\n=== FIELD-BY-FIELD DIFF OF THE ATTRIBUTION OBJECTS ===")
    objs = {r["arm"]: (r.get("final") or {}) for r in out}
    keys = sorted({k for o in objs.values() for k in o})
    print("%-28s %-26s %-26s %-26s" % ("field", "N0 no-click", "N1 click+click",
                                       "N2 click only"))
    for k in keys:
        vals = [str(objs[a].get(k, "-"))[:25] for a in ("N0", "N1", "N2")]
        mark = "  <-- DIFFERS" if len(set(vals)) > 1 else ""
        print("%-28s %-26s %-26s %-26s%s" % (k, vals[0], vals[1], vals[2], mark))
    n0, n1 = json.dumps(objs["N0"], sort_keys=True), json.dumps(objs["N1"],
                                                               sort_keys=True)
    print("\nN0 vs N1 attribution objects IDENTICAL: %s" % (n0 == n1))
    print("\n=== VERDICTS ===")
    for r in out:
        print("  %s -> %s" % (r["arm"], r["verdict"]))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
