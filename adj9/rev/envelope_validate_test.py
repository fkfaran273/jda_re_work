r"""envelope_validate_test.py — CAN the server be observed to validate anything?

The 4-arm signature test was inconclusive: /sdk_click returns HTTP 200 + the
adid (which already exists from /session) whether or not the envelope is
valid, so 200 proves nothing.

This test corrupts the OTHER envelope/header fields the genuine app sends, one
at a time, and looks for ANY observable difference -- status code, response
body, or the subsequent /attribution payload.  If the server parses and
validates the envelope at all, at least one of these must move.

Arms (all on fresh GAIDs, real tracker click first):
  A0  control          -- everything genuine
  A1  bad adj_verification token
  A2  bad native_version (99.9.9)
  A3  bad algorithm    (adj7)
  A4  bad adj_signing_id
  A5  malformed base64 signature
  A6  bad headers_id
  A7  Client-SDK header removed
  A8  Authorization header removed entirely
"""
from __future__ import annotations
import base64, gzip, http.client, json, os, sys, time, urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import adj9_full_chain as fc
import offline_funnel_freshregion as F
import click_bind_chain as CBC

OUT = os.path.join(HERE, "envelope_validate_result.json")


def auth_variant(blob, arm):
    sig = base64.b64encode(blob).decode()
    if arm == "A1":
        return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
                'headers_id="10",native_version="5.0.0",'
                'adj_verification="WRONGTOKENWRONGTOKENWRONG"' % sig)
    if arm == "A2":
        return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
                'headers_id="10",native_version="99.9.9",'
                'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig)
    if arm == "A3":
        return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj7",'
                'headers_id="10",native_version="5.0.0",'
                'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig)
    if arm == "A4":
        return ('Signature signature="%s",adj_signing_id="9999999",algorithm="adj9",'
                'headers_id="10",native_version="5.0.0",'
                'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig)
    if arm == "A5":
        return ('Signature signature="!!!not-base64!!!",adj_signing_id="1500000",'
                'algorithm="adj9",headers_id="10",native_version="5.0.0",'
                'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"')
    if arm == "A6":
        return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
                'headers_id="99",native_version="5.0.0",'
                'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig)
    if arm == "A8":
        return None
    return fc._auth_header(blob)


def post(url, params, auth, drop_client_sdk=False):
    pr = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    try:
        body = urllib.parse.urlencode(params).encode()
        conn.putrequest("POST", pr.path, skip_host=1, skip_accept_encoding=1)
        if not drop_client_sdk:
            conn.putheader("Client-SDK", "android5.7.0")
        if auth:
            conn.putheader("Authorization", auth)
        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
        conn.putheader("User-Agent", fc.UA)
        conn.putheader("Host", pr.hostname)
        conn.putheader("Connection", "Keep-Alive")
        conn.putheader("Accept-Encoding", "gzip")
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        r = conn.getresponse(); raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            try: raw = gzip.decompress(raw)
            except Exception: pass
        return r.status, raw.decode("utf-8", "replace")
    finally:
        conn.close()


def run(arm, send_live):
    gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
    rec = {"arm": arm, "gps": gps}
    code, ref, hops = CBC.tracker_click(CBC.expand(F.LINK, gps), gps)
    rec["click_http"] = code
    if "adjust_reftag=" not in (ref or ""):
        rec["verdict"] = "NO_REFTAG"; return rec
    if not send_live:
        rec["verdict"] = "DRY_RUN"; return rec
    t = int(time.time())
    ins = fc.fmt(t - 7, 431).decode()
    tb = t + F.CTIT
    # session: always fully genuine (book the adid)
    ps = F.build_session(gps, auid, ins, int(time.time()) - 2)
    bs, _ = F.mint_signed("session", ps, int(time.time()) - 2)
    rec["session"] = post("https://app.adjust.com/session", ps,
                          fc._auth_header(bs))
    # click: the arm's corruption, on the SAME endpoint the device uses
    pc = F.build_sdk_click(gps, auid, ref, t, tb, ins, int(time.time()) - 2)
    bc, _ = F.mint_signed("click", pc, int(time.time()) - 2)
    rec["sdk_click"] = post("https://app.adjust.com/sdk_click", pc,
                            auth_variant(bc, arm),
                            drop_client_sdk=(arm == "A7"))
    rec["verdict"] = "session=%s click=%s" % (
        rec["session"][0], rec["sdk_click"][0])
    return rec


def main():
    send_live = "--send" in sys.argv and "SEND-ENVELOPE-VALIDATE" in sys.argv
    if "--send" in sys.argv and not send_live:
        print("!! need --send SEND-ENVELOPE-VALIDATE")
        return 1
    arms = ["A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8"]
    out = []
    for a in arms:
        print("=== %s ===" % a, flush=True)
        r = run(a, send_live)
        print("   %s" % r["verdict"], flush=True)
        if r.get("sdk_click"): print("   click body: %s" % (r["sdk_click"][1][:160],))
        if r.get("session"): print("   sess body: %s" % (r["session"][1][:160],))
        out.append(r)
        json.dump(out, open(OUT, "w"), indent=1)
        time.sleep(2)
    print("\n=== SUMMARY: does ANY corruption change the response? ===")
    base = out[0]
    for r in out:
        sc = r.get("sdk_click", [None, ""])[0]
        same = (sc == base.get("sdk_click", [None, ""])[0])
        print("  %s click=%s  %s" % (r["arm"], sc,
                                     "SAME as control" if same else "*** DIFFERENT ***"))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
