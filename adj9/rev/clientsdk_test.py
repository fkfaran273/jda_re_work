r"""clientsdk_test.py — what exactly does the Client-SDK validator check?

A7 (Client-SDK header removed) was the ONLY arm in envelope_validate_test.py
that changed the response: /sdk_click returned
    400 {"error":"SDK click failed (unsupported sdk)"}
Every envelope corruption (adj_verification, native_version, algorithm,
adj_signing_id, headers_id, base64, whole Authorization) returned 200.

So the one thing the server demonstrably validates on this path is the
Client-SDK header -- which is NOT covered by the adj9 signature.  This maps
its acceptance: which values pass, which are rejected, whether the body
declares a matching client_sdk, and whether the validator's verdict has any
effect on attribution (i.e. whether it gates the JOIN, not just the 400).

Arms:
  C0  android5.7.0   (genuine)
  C1  android5.6.0   (older)
  C2  android5.0.0
  C3  ios5.7.0        (wrong platform)
  C4  android99.0.0   (absurd version)
  C5  ""              (empty)
  C6  GARBAGE         (non-version string)
  C7  android5.7.0 but body client_sdk claim mismatched -> does desc10 care?
"""
from __future__ import annotations
import gzip, http.client, json, os, sys, time, urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import adj9_full_chain as fc
import offline_funnel_freshregion as F
import click_bind_chain as CBC

OUT = os.path.join(HERE, "clientsdk_result.json")
VALUES = [("C0", "android5.7.0"), ("C1", "android5.6.0"), ("C2", "android5.0.0"),
          ("C3", "ios5.7.0"), ("C4", "android99.0.0"), ("C5", ""),
          ("C6", "GARBAGE")]


def call(url, params, auth, client_sdk):
    pr = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    try:
        body = urllib.parse.urlencode(params).encode()
        conn.putrequest("POST", pr.path, skip_host=1, skip_accept_encoding=1)
        if client_sdk is not None:
            conn.putheader("Client-SDK", client_sdk)
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


def main():
    if "--send" not in sys.argv:
        print("dry-run; arms:")
        for t, v in VALUES: print("  %s = %r" % (t, v))
        return 0
    out = []
    for tag, val in VALUES:
        gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
        code, ref, hops = CBC.tracker_click(CBC.expand(F.LINK, gps), gps)
        rec = {"arm": tag, "client_sdk": val, "gps": gps, "click_http": code}
        if "adjust_reftag=" not in (ref or ""):
            rec["verdict"] = "NO_REFTAG"; out.append(rec); continue
        t0 = int(time.time())
        ins = fc.fmt(t0 - 7, 431).decode(); tb = t0 + F.CTIT
        ps = F.build_session(gps, auid, ins, int(time.time()) - 2)
        bs, _ = F.mint_signed("session", ps, int(time.time()) - 2)
        # session ALWAYS uses the genuine Client-SDK, so it books
        rec["session"] = call("https://app.adjust.com/session", ps,
                              fc._auth_header(bs), "android5.7.0")
        pc = F.build_sdk_click(gps, auid, ref, t0, tb, ins, int(time.time()) - 2)
        bc, _ = F.mint_signed("click", pc, int(time.time()) - 2)
        rec["sdk_click"] = call("https://app.adjust.com/sdk_click", pc,
                                fc._auth_header(bc), val)
        sc, body = rec["sdk_click"]
        rec["verdict"] = "click=%s %s" % (sc, body[:90])
        print("%s client_sdk=%-14r -> %s" % (tag, val, rec["verdict"]), flush=True)
        out.append(rec)
        json.dump(out, open(OUT, "w"), indent=1)
        time.sleep(2)
    print("\n=== SUMMARY ===")
    for r in out:
        sc = r.get("sdk_click", [None, ""])[0]
        print("  %s %-16r http=%s" % (r["arm"], r.get("client_sdk"), sc))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
