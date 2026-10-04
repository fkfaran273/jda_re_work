r"""header_ablate_test.py — systematic hunt for server-side validators.

envelope_validate_test.py found ONE live validator: removing the Client-SDK
header turns /sdk_click into
    400 {"error":"SDK click failed (unsupported sdk)"}
while corrupting the whole adj9 envelope changes nothing.  So the server does
validate what we send -- we just had not ablated anything outside the
Authorization header.

This ablates the transport layer one header at a time (the systematic version
of the lucky A7 find) and records status + body for each, so we learn the
full set of things the server actually checks.  Each arm: fresh GAID, real
tracker click, genuine signed /session (so the adid books), then /sdk_click
with exactly one thing changed.

Arms:
  H0  control, all headers, Accept-Encoding: gzip
  H1  no Client-SDK              (known 400 -- regression check)
  H2  no User-Agent
  H3  no Content-Type
  H4  no Host
  H5  no Connection
  H6  no Accept-Encoding
  H7  Accept-Encoding: identity  (what our sender used to send)
  H8  no Authorization           (envelope irrelevant -- control)
  H9  extra unknown X-Adjust-Debug header
  H10 iPhone User-Agent over an android body
"""
from __future__ import annotations
import gzip, http.client, json, os, sys, time, urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import adj9_full_chain as fc
import offline_funnel_freshregion as F
import click_bind_chain as CBC

OUT = os.path.join(HERE, "header_ablate_result.json")

IPHONE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148")

# arm -> (drop_headers, overrides)
ARMS = {
    "H0":  ([], {}),
    "H1":  (["Client-SDK"], {}),
    "H2":  (["User-Agent"], {}),
    "H3":  (["Content-Type"], {}),
    "H4":  (["Host"], {}),
    "H5":  (["Connection"], {}),
    "H6":  (["Accept-Encoding"], {}),
    "H7":  ([], {"Accept-Encoding": "identity"}),
    "H8":  (["Authorization"], {}),
    "H9":  ([], {"X-Adjust-Debug": "1"}),
    "H10": ([], {"User-Agent": IPHONE_UA}),
}

BASE = [
    ("Client-SDK", "android5.7.0"),
    ("Content-Type", "application/x-www-form-urlencoded"),
    ("User-Agent", fc.UA),
    ("Host", "app.adjust.com"),
    ("Connection", "Keep-Alive"),
    ("Accept-Encoding", "gzip"),
]


def post(path_url, params, auth, drop, over):
    pr = urllib.parse.urlsplit(path_url)
    body = urllib.parse.urlencode(params).encode()
    hdrs = []
    for k, v in BASE:
        if k in drop:
            continue
        hdrs.append((k, over.get(k, v)))
    for k, v in over.items():
        if k not in dict(BASE):
            hdrs.append((k, v))
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    try:
        conn.putrequest("POST", pr.path, skip_host=1, skip_accept_encoding=1)
        if auth and "Authorization" not in drop:
            conn.putheader("Authorization", auth)
        for k, v in hdrs:
            conn.putheader(k, v)
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        r = conn.getresponse(); raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            try: raw = gzip.decompress(raw)
            except Exception: pass
        return r.status, raw.decode("utf-8", "replace")
    finally:
        conn.close()


def main():
    live = "--send" in sys.argv
    if not live:
        for a in sorted(ARMS):
            print("  %s drop=%s over=%s" % (a, ARMS[a][0], ARMS[a][1]))
        return 0
    out = []
    for arm in sorted(ARMS):
        drop, over = ARMS[arm]
        gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
        code, ref, hops = CBC.tracker_click(CBC.expand(F.LINK, gps), gps)
        rec = {"arm": arm, "drop": drop, "over": over, "gps": gps,
               "click_http": code}
        if "adjust_reftag=" not in (ref or ""):
            rec["verdict"] = "NO_REFTAG"; out.append(rec); continue
        t = int(time.time())
        ins = fc.fmt(t - 7, 431).decode(); tb = t + F.CTIT
        # session always fully genuine -> books the adid
        ps = F.build_session(gps, auid, ins, int(time.time()) - 2)
        bs, _ = F.mint_signed("session", ps, int(time.time()) - 2)
        rec["session"] = post("https://app.adjust.com/session", ps,
                              fc._auth_header(bs), [], {})
        # click: exactly one thing changed
        pc = F.build_sdk_click(gps, auid, ref, t, tb, ins, int(time.time()) - 2)
        bc, _ = F.mint_signed("click", pc, int(time.time()) - 2)
        sc, body = post("https://app.adjust.com/sdk_click", pc,
                        fc._auth_header(bc), drop, over)
        rec["sdk_click"] = [sc, body[:200]]
        rec["verdict"] = "click=%s %s" % (sc, body[:80])
        print("%-4s drop=%-16s -> %s" % (arm, ",".join(drop) or "-",
                                         rec["verdict"]), flush=True)
        out.append(rec)
        json.dump(out, open(OUT, "w"), indent=1)
        time.sleep(2)
    print("\n=== SUMMARY: which ablations change the /sdk_click response? ===")
    base = next((r for r in out if r["arm"] == "H0"), None)
    bstat = base.get("sdk_click", [None])[0] if base else None
    for r in out:
        sc = r.get("sdk_click", [None, ""])[0]
        mark = "SAME as control" if sc == bstat else "*** DIFFERENT ***"
        print("  %-4s http=%-5s %s   %s" % (r["arm"], sc, mark,
                                           (r.get("sdk_click") or ["", ""])[1][:70]))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
