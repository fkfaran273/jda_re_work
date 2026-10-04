r"""replay_winner.py — replay a GENUINE winner record through OUR signer.

The user's challenge: "if the device can do it, we can too — something is still
unverified."  This replays the genuine winning install/click claim maps
byte-for-byte through OUR mint (fresh-region adj9) and re-drives them live, so
that the ONLY variable is whose code produced the envelope.

Control rows (from adj9/rev/win_capture/, GAIDs distinct from the connected
device ZD2228MY3X / f476b3d4):
  row0 = session   gaid 7cc81be0  installed 2026-09-14T17:52:12.431+0530
  row1 = click     gaid 7cc81be0  referrer utm_source=google-play&utm_medium=organic
  row2 = session   gaid 2db6422f  installed 2026-09-24T19:03:25.431+0200
  row3 = click     gaid 2db6422f
  row4/5 = attribution

Note these winners were themselves ORGANIC referrer installs, so the expected
result of a correct replay is: signature accepted, request accepted.  What this
proves is whether OUR envelope is accepted for the server on a known-good
record -- the missing control in every prior run.
"""
from __future__ import annotations
import argparse, gzip, http.client, json, os, sys, time, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import adj9_full_chain as fc
import offline_funnel_freshregion as F
import mint_pipeline as MP
import decoder as D

OUT = os.path.join(HERE, "replay_winner_result.json")
APP_TOKEN = F.APP_TOKEN


def send(url, params, blob, method="POST"):
    pr = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    try:
        hdrs = {"Client-SDK": "android5.7.0",
                "Authorization": fc._auth_header(blob),
                "User-Agent": fc.UA, "Host": pr.hostname,
                "Connection": "Keep-Alive", "Accept-Encoding": "identity"}
        if method == "POST":
            body = urllib.parse.urlencode(params).encode()
            conn.putrequest("POST", pr.path, skip_host=1, skip_accept_encoding=1)
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            hdrs["Content-Length"] = str(len(body))
            for k, v in hdrs.items(): conn.putheader(k, v)
            conn.endheaders(body)
        else:
            path = pr.path + "?" + urllib.parse.urlencode(
                params, quote_via=urllib.parse.quote)
            conn.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
            for k, v in hdrs.items(): conn.putheader(k, v)
            conn.endheaders()
        r = conn.getresponse(); raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            try: raw = gzip.decompress(raw)
            except Exception: pass
        return r.status, raw.decode("utf-8", "replace")
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--confirm", default="")
    ap.add_argument("--rows", default="0,1,2,3,4,5")
    args = ap.parse_args()
    send_live = bool(args.send and args.confirm == "SEND-REPLAY-WINNER")
    if args.send and not send_live:
        print("!! --send without exact --confirm; dry-run.")
        return 1

    rows = D.claims_from_capture()
    want = [int(x) for x in args.rows.split(",")]
    out = []
    for i in want:
        claims, blob0 = rows[i]
        kind = claims.get("activity_kind", "session")
        gaid = claims.get("gps_adid")
        # rebuild the WIRE params from the genuine claim map, minus signing
        # keys (those live in the Authorization header, not the body).
        p = {k: v for k, v in claims.items()
             if k not in ("activity_kind", "client_sdk", "adj_verification",
                          "headers_id", "adj_signing_id", "native_version",
                          "algorithm")}
        rec = {"row": i, "kind": kind, "gps_adid": gaid,
               "n_wire": len(p), "genuine_blob": blob0.hex()}
        # mint with OUR signer, fresh region
        sec = int(time.time()) - 2
        b1, info = F.mint_signed(kind, p, sec)
        rec["our_mint"] = {"status": info["status"], "n_claims": info["n_claims"],
                           "desc10": info["desc10_len"],
                           "unpadded": info["unpadded"],
                           "len": len(b1), "second": info["second"]}
        print("row %d %-12s wire=%d claims=%d desc10=%d status=%s" % (
            i, kind, len(p), info["n_claims"], info["desc10_len"],
            info["status"]), flush=True)
        if not send_live:
            rec["verdict"] = "DRY_RUN"
            out.append(rec); continue
        url = {"session": "https://app.adjust.com/session",
               "click": "https://app.adjust.com/sdk_click",
               "attribution": "https://app.adjust.com/attribution"}[kind]
        st, body = send(url, p, b1, method=("GET" if kind == "attribution" else "POST"))
        rec["http"] = st
        rec["resp"] = body[:500]
        rec["verdict"] = "HTTP %d" % st
        try:
            j = json.loads(body)
            att = j.get("attribution")
            if att:
                rec["attribution"] = att
                rec["verdict"] = "%s net=%s tracker=%s" % (
                    st, att.get("network"), att.get("tracker_token"))
        except Exception:
            pass
        print("   -> HTTP %s  %s" % (st, rec["verdict"]), flush=True)
        out.append(rec)
        time.sleep(3)
    json.dump(out, open(OUT, "w"), indent=1, default=str)
    print("\nsaved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
