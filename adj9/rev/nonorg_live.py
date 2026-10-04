r"""nonorg_live.py — live click with the GENUINE NON-ORGANIC body (47 keys).

The genuine non-organic click (saz _saz_x/raw/2_c.txt, GAID d016e7e4, tracker
24pxw9rl / VKM Digital Yeni) carries 47 wire keys including click_time,
click_time_server, install_begin_time, install_begin_time_server,
install_version and google_play_instant.  Earlier work wrongly stripped the
four click-time fields after searching only the ORGANIC captures.  Both
harnesses now emit the full 47-key body via F.build_sdk_click.

Timing relations measured from that record:
    click_time - click_time_server       = +2s
    install_begin - install_begin_server = +2s
    installed_at - install_begin_time    = +7s
    created_at  - click_time             = +273s

Arms:
  P0  click -> session -> sdk_click            (the corrected full body)
  P1  click -> session, NO sdk_click
  P2  NO click at all (session only)           (baseline for comparison)
"""
from __future__ import annotations
import base64, gzip, http.client, json, os, sys, time, urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M
import adj9_full_chain as F
import F as FF
import click_bind_chain as CBC
import offline_funnel_freshregion as FFN

UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
ADJ_V = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
OUT = os.path.join(HERE, "nonorg_live_result.json")
POLL = (10, 30, 75)


def _req(method, path, params, auth):
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


def mint(params, kind, sec):
    claims = dict(params)
    for k, v in (("adj_verification", ADJ_V), ("adj_signing_id", "1500000"),
                 ("headers_id", "10"), ("native_version", "5.0.0"),
                 ("activity_kind", kind), ("client_sdk", "android5.7.0")):
        claims.setdefault(k, v)
    padded, unpadded = M.claims_for_law(claims, kind)
    import struct
    d0w, d2w, d4w = FF.region(sec, 0, 0, head=M.DEVICE_SELECTORS)
    by = {0: (36, 0, b"".join(struct.pack(">I", w) for w in d0w)),
          9: (5, 0, bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")),
          8: (4, 0, bytes.fromhex("bffffffffffffd1f0007000000000000")),
          4: (8, 0, b"".join(struct.pack(">I", w) for w in d4w)),
          2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    blob, _ = M.finex_mint([by[i] for i in M.VA_ORDER], sec)
    return blob


def auth_of(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_V))


def score(status, body):
    if status != 200:
        return "FAILURE (HTTP %d: %s)" % (status, body[:100])
    try:
        att = json.loads(body).get("attribution")
    except Exception:
        return "FAILURE (unparseable)"
    if not att:
        return "FAILURE (200, no attribution object)"
    net, tok = att.get("network"), att.get("tracker_token")
    if net and net != "Organic" and tok and tok != "wy7261z":
        return "*** GOAL MET: %s / %s ***" % (net, tok)
    return "ORGANIC (%s / %s / eng=%s)" % (net, tok, att.get("engagement_time"))


def run(tag, do_click, do_click_req):
    gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
    rec = {"arm": tag, "gps": gps}
    referrer = None
    if do_click:
        code, referrer, _ = CBC.tracker_click(CBC.expand(FFN.LINK, gps), gps)
        rec["click"] = {"http": code, "referrer": (referrer or "")[:110]}
        if not referrer:
            rec["verdict"] = "NO_REFTAG"; return rec
    t_click = int(time.time())
    # genuine timing: installed_at = t_click + 273 (created_at - click_time)
    sec = t_click + 275
    ins = F.fmt(sec - 55, 774).decode()          # created_at - installed_at = 55s
    tb = sec - 55 - 7                            # install_begin = installed - 7s
    sp = FFN.build_session(gps, auid, ins, sec)
    rec["session_keys"] = len(sp)
    st, bd = _req("POST", "/session", sp, auth_of(mint(sp, "session", sec)))
    rec["session"] = [st, bd[:200]]
    if do_click_req and referrer:
        cp = FFN.build_sdk_click(gps, auid, referrer, t_click, tb, ins, sec)
        rec["click_keys"] = len(cp)
        stc, bdc = _req("POST", "/sdk_click", cp,
                        auth_of(mint(cp, "click", sec)))
        rec["sdk_click"] = [stc, bdc[:200]]
    atts = []
    for w in POLL:
        time.sleep(w)
        ap = FFN.build_attribution(gps, auid, int(time.time()))
        sa, bda = _req("GET", "/attribution", ap,
                       auth_of(mint(ap, "attribution", int(time.time()))))
        try: a = json.loads(bda).get("attribution")
        except Exception: a = None
        atts.append({"http": sa, "attribution": a})
        if a: break
    rec["final"] = atts[-1].get("attribution") if atts else None
    rec["verdict"] = score(atts[-1]["http"], json.dumps(
        {"attribution": atts[-1].get("attribution")})) if rec["final"] else "NO_ATTRIBUTION"
    return rec


def main():
    out = []
    for tag, dc, dcr in (("P0", True, True), ("P1", True, False),
                         ("P2", False, False)):
        print("=== %s  click=%s sdk_click=%s ===" % (tag, dc, dcr), flush=True)
        r = run(tag, dc, dcr)
        print("   session=%s keys=%s  click_keys=%s  -> %s"
              % ((r.get("session") or [None])[0], r.get("session_keys"),
                 r.get("click_keys"), r["verdict"]), flush=True)
        if r.get("sdk_click"): print("   sdk_click: %s" % (r["sdk_click"],),)
        out.append(r)
        json.dump(out, open(OUT, "w"), indent=1)
    print("\n=== DIFF ===")
    objs = {r["arm"]: (r.get("final") or {}) for r in out}
    for k in sorted({k for o in objs.values() for k in o}):
        v = [str(objs[a].get(k, "-"))[:24] for a in ("P0", "P1", "P2")]
        print("%-26s %-24s %-24s %-24s%s" % (k, v[0], v[1], v[2],
                                              "  <-- DIFFERS" if len(set(v)) > 1 else ""))
    print("\n=== VERDICTS ===")
    for r in out:
        print("  %s -> %s" % (r["arm"], r["verdict"]))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
