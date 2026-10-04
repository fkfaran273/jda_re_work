r"""join_sig_test.py — does the SERVER verify the signature on the click/join path?

Direct test of the open question: booking (/session) is signature-agnostic
(unsigned_control.py proved that). But nobody has shown the JOIN path behaves
the same. If /sdk_click's signature is checked server-side, then feeding a
corrupt/empty/garbage signature must change the server's behaviour (reject,
4xx, or a different response/attribution). If all four arms behave
identically, the join path does not verify the signature either — proving the
signature is not the join gate.

Each arm: FRESH GAID (never the connected device's) + its own real tracker
click (genuine 302 adjust_reftag) + valid /session + /sdk_click with the
signature state varied. Then poll /attribution and compare:
  * /sdk_click HTTP status + response body
  * resulting attribution (network / tracker_token)

arms: S0 valid | S1 1-bit flipped | S2 empty | S3 garbage
"""
from __future__ import annotations
import argparse, base64, json, os, sys, time, uuid

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import adj9_full_chain as fc
import offline_funnel_freshregion as F
import click_bind_chain as CBC

OUT = os.path.join(HERE, "join_sig_test_result.json")
POLL = [0, 8]


def send_with_auth(url, params, blob_or_state, method="POST"):
    """Send with Authorization derived from a signature state."""
    if blob_or_state == "EMPTY":
        auth = None
    elif blob_or_state == "GARBAGE":
        bogus = base64.b64encode(b"\x00" * 192).decode()
        auth = ('Signature signature="%s",adj_signing_id="1500000",'
                'algorithm="adj9",headers_id="10",native_version="5.0.0",'
                'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % bogus)
    else:
        auth = fc._auth_header(blob_or_state)
    import http.client, urllib.parse
    pr = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    try:
        if method == "POST":
            body = urllib.parse.urlencode(params).encode()
            conn.putrequest("POST", pr.path, skip_host=1, skip_accept_encoding=1)
            conn.putheader("Client-SDK", "android5.7.0")
            if auth: conn.putheader("Authorization", auth)
            conn.putheader("Content-Type", "application/x-www-form-urlencoded")
            conn.putheader("User-Agent", fc.UA)
            conn.putheader("Host", pr.hostname)
            conn.putheader("Connection", "Keep-Alive")
            conn.putheader("Accept-Encoding", "identity")
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
        else:
            path = pr.path + "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            conn.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
            conn.putheader("Client-SDK", "android5.7.0")
            if auth: conn.putheader("Authorization", auth)
            conn.putheader("User-Agent", fc.UA)
            conn.putheader("Host", pr.hostname)
            conn.putheader("Connection", "Keep-Alive")
            conn.putheader("Accept-Encoding", "identity")
            conn.endheaders()
        resp = conn.getresponse()
        raw = resp.read()
        if raw[:2] == b"\x1f\x8b":
            import gzip
            try: raw = gzip.decompress(raw)
            except Exception: pass
        return resp.status, raw.decode("utf-8", "replace")
    finally:
        conn.close()


def run_arm(tag, sig_state, send_live):
    gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
    rec = {"arm": tag, "sig_state": sig_state, "gps": gps}
    link = CBC.expand(F.LINK, gps)
    t_click = int(time.time())
    code, ref, hops = CBC.tracker_click(link, gps)
    rec["click_http"] = code
    rec["referrer"] = ref
    if "adjust_reftag=" not in (ref or ""):
        rec["verdict"] = "NO_REFTAG"; return rec
    if not send_live:
        rec["verdict"] = "DRY_RUN"; return rec
    tb = t_click + F.CTIT
    ins = fc.fmt(tb + F.INS_LAG, 431).decode()
    # /session always valid signature
    sec_s = int(time.time()) - 2
    ps = F.build_session(gps, auid, ins, sec_s)
    bs, _ = F.mint_signed("session", ps, sec_s)
    s_s, r_s = send_with_auth("https://app.adjust.com/session", ps, bs)
    rec["session_http"] = s_s
    # /sdk_click with the arm's signature state
    sec_c = int(time.time()) - 2
    pc = F.build_sdk_click(gps, auid, ref, t_click, tb, ins, sec_c)
    bc, _ = F.mint_signed("click", pc, sec_c)
    if sig_state == "FLIP":
        b = bytearray(bc); b[16] ^= 0x01; blob_or_state = bytes(b)
    elif sig_state == "EMPTY":
        blob_or_state = "EMPTY"
    elif sig_state == "GARBAGE":
        blob_or_state = "GARBAGE"
    else:
        blob_or_state = bc
    s_c, r_c = send_with_auth("https://app.adjust.com/sdk_click", pc, blob_or_state)
    rec["sdk_click_http"] = s_c
    rec["sdk_click_resp"] = r_c[:400]
    # poll attribution
    last = None
    for wait in POLL:
        if wait: time.sleep(wait)
        sec_a = int(time.time()) - 2
        pa = F.build_attribution(gps, auid, sec_a)
        ba, _ = F.mint_signed("attribution", pa, sec_a)
        s_a, r_a = send_with_auth("https://app.adjust.com/attribution", pa, ba, method="GET")
        try: att = json.loads(r_a).get("attribution")
        except Exception: att = None
        if att: last = att
    rec["attribution"] = last
    if last and last.get("network") and last["network"] != "Organic":
        rec["verdict"] = "NON_ORGANIC %s / %s" % (last.get("tracker_token"), last["network"])
    elif last:
        rec["verdict"] = "ORGANIC %s" % last.get("tracker_token")
    else:
        rec["verdict"] = "NO_ATTRIBUTION"
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--confirm", default="")
    args = ap.parse_args()
    send_live = bool(args.send and args.confirm == "SEND-JOIN-SIGTEST")
    if args.send and not send_live:
        print("!! --send without exact --confirm; dry-run.")
    arms = [("S0", "VALID"), ("S1", "FLIP"), ("S2", "EMPTY"), ("S3", "GARBAGE")]
    print("mode:", "SEND" if send_live else "DRY-RUN")
    for t, st in arms: print("  %s = %s" % (t, st))
    if not send_live:
        return 0
    results = []
    for t, st in arms:
        print("=== arm %s (%s) ===" % (t, st), flush=True)
        r = run_arm(t, st, True)
        print("  click=%s session=%s sdk_click=%s -> %s" % (
            r.get("click_http"), r.get("session_http"),
            r.get("sdk_click_http"), r["verdict"]), flush=True)
        if r.get("sdk_click_resp"): print("   sdk_click resp:", r["sdk_click_resp"][:160])
        results.append(r)
    json.dump(results, open(OUT, "w"), indent=1)
    print("\n=== COMPARISON (does the server treat bad sigs differently?) ===")
    for r in results:
        print("  %s %-8s sdk_click=%s att=%s" % (
            r["arm"], r["sig_state"], r.get("sdk_click_http"),
            (r.get("attribution") or {}).get("network")))
    print("saved", OUT)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
