r"""unsigned_control.py — THE decisive control: does the server book an install
with NO (or a garbage) Authorization header?

Why this is the control that matters
------------------------------------
The corrected fresh-region funnel (offline_funnel_freshregion.py) returned
HTTP 200 + a REAL adid for BOTH a valid signature AND a one-bit-flipped
signature.  Two very different explanations remain:

  (A) the server does not gate install BOOKING on the adj9 signature, or
  (B) our signature is malformed enough that the server treats the request as
      effectively UNSIGNED and books it anyway (which would mean our entire
      signature-making path is wrong and we would not know).

This probe separates them.  Same /session request, same fresh GAID, three arms
that differ ONLY in the Authorization header:
  S0  valid signature            (our normal fresh-region mint)
  S1  one-bit-flipped signature  (deliberately invalid, like the control cell)
  S2  NO Authorization header    (unsigned)  <-- the new decisive arm
  S3  garbage Authorization      (valid b64, not our blob)

If S2/S3 book the install exactly like S0/S1 => the server is NOT gating
booking on the signature (A is true); our signature work is then about whatever
the server DOES use the signature for (the click join / engagement), not
booking.  If S2/S3 are REJECTED (400) while S0/S1 book => our signature is
genuinely valid and meaningful (B is false), and the earlier bit-flip result
needs a different explanation.

Read-only on the server in spirit: it does book a /session install record per
arm (that is unavoidable — it is the probe).  It fires NO click, so it cannot
earn or disturb any campaign attribution.  Uses fresh uuid4 GAIDs only.

Usage:
  python unsigned_control.py                       # dry-run: mints + self-checks, NO send
  python unsigned_control.py --send --confirm SEND-UNSIGNED-CONTROL
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_full_chain as fc
import offline_funnel_freshregion as OFF   # reuse build_session / mint_signed

fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"

OUT = os.path.join(HERE, "unsigned_control_result.json")


def _send_with_auth(params, blob_or_none, method="POST"):
    """Send /session, optionally WITHOUT (or with garbage) the Authorization.

    Reuses fc.send's exact header order/UA/host, but takes control of the
    auth header value.  blob_or_none:
      bytes -> use fc._auth_header(blob)
      "GARBAGE" -> a syntactically valid but bogus Signature header
      None -> send with NO Authorization header at all
    """
    import http.client
    import urllib.parse
    auth = None
    if isinstance(blob_or_none, bytes):
        auth = fc._auth_header(blob_or_none)
    elif blob_or_none == "GARBAGE":
        import base64
        bogus = base64.b64encode(b"\x00" * 192).decode()
        auth = ('Signature signature="%s",adj_signing_id="1500000",'
                'algorithm="adj9",headers_id="10",native_version="5.0.0",'
                'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % bogus)
    url = "https://app.adjust.com/session"
    pr = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    try:
        body = urllib.parse.urlencode(params).encode()
        conn.putrequest("POST", pr.path, skip_host=1, skip_accept_encoding=1)
        conn.putheader("Client-SDK", "android5.7.0")
        if auth:
            conn.putheader("Authorization", auth)
        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
        conn.putheader("User-Agent", fc.UA)
        conn.putheader("Host", pr.hostname)
        conn.putheader("Connection", "Keep-Alive")
        conn.putheader("Accept-Encoding", "identity")   # avoid gzip ambiguity
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", "replace")
        return resp.status, data
    except Exception as e:
        return "ERR", str(e)[:200]
    finally:
        conn.close()


def arm(name, gps, auid, ins, second):
    p = OFF.build_session(gps, auid, ins, second)
    if name == "S0_valid":
        blob, _ = OFF.mint_signed("session", p, second)
        st, body = _send_with_auth(p, blob)
    elif name == "S1_bitflip":
        blob, _ = OFF.mint_signed("session", p, second, flip_bit=True)
        st, body = _send_with_auth(p, blob)
    elif name == "S2_unsigned":
        st, body = _send_with_auth(p, None)
    elif name == "S3_garbage":
        st, body = _send_with_auth(p, "GARBAGE")
    booked = None
    try:
        j = json.loads(body)
        booked = j.get("adid")
    except Exception:
        pass
    return {"arm": name, "gps": gps, "auid": auid, "http": st,
            "adid": booked, "body": body[:400]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--confirm", default="")
    args = ap.parse_args()
    send_live = bool(args.send and args.confirm == "SEND-UNSIGNED-CONTROL")
    if args.send and not send_live:
        print("!! need exact --confirm SEND-UNSIGNED-CONTROL; forcing dry-run.")

    # always prove the valid arm mints cleanly first
    probe = str(uuid.uuid4())
    second = int(time.time()) - 2
    ins = fc.fmt(second - 170, 774).decode()
    p = OFF.build_session(probe, str(uuid.uuid4()), ins, second)
    b, info = OFF.mint_signed("session", p, second)
    print("=== pre-send mint check ===")
    print("  valid mint 192B:", len(b) == 192, " status:", info["status"],
          " claims:", info["n_claims"])

    if not send_live:
        print("\n=== DRY-RUN (no traffic). Add --send --confirm "
              "SEND-UNSIGNED-CONTROL to run the 4 arms. ===")
        return 0

    results = []
    for name in ("S0_valid", "S1_bitflip", "S2_unsigned", "S3_garbage"):
        gps, auid = str(uuid.uuid4()), str(uuid.uuid4())
        second = int(time.time()) - 2
        ins = fc.fmt(second - 170, 774).decode()
        rec = arm(name, gps, auid, ins, second)
        results.append(rec)
        print("  %-12s http=%-5s adid=%s" %
              (name, rec["http"], rec["adid"]), flush=True)
        time.sleep(2)

    json.dump(results, open(OUT, "w"), indent=1)
    print("\n=== VERDICT TABLE ===")
    for r in results:
        print("  %-12s http=%-5s adid=%s" % (r["arm"], r["http"], r["adid"]))
    booked = [r["arm"] for r in results if r["adid"]]
    unsigned_booked = any(r["adid"] for r in results
                          if r["arm"] in ("S2_unsigned", "S3_garbage"))
    print("\n  arms that booked an adid:", booked)
    if unsigned_booked:
        print("  => SIGNATURE IS NOT THE BOOKING GATE (unsigned books too).")
        print("     The click JOIN (not the signature) is the remaining gate.")
    else:
        print("  => SIGNATURE MATTERS: unsigned/garbage rejected, signed booked.")
        print("     Our signature is genuinely valid; bit-flip result needs rethink.")
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
