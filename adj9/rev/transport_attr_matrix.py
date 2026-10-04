#!/usr/bin/env python3
r"""transport_attr_matrix.py — the sharpest, genuinely discriminating read.

Identity 2db6422f-0045-41bd-99ef-2264d70beec9 has a REAL, non-Organic
attribution on the server:

    tracker_token  24xg6t54
    tracker_name   VKM Digital Yeni::AH::vkm_0926_36::cline_1p8t3
    network        VKM Digital Yeni
    engagement_time 2026-09-24T17:03:18Z

so /attribution is a true read-oracle on this identity: a correct signature
returns the campaign, anything else falls back to Organic.  (Identity
363e5b78 is useless as an oracle — it genuinely IS Organic, so every arm
returns the same correct answer and the endpoint looks signature-blind.)

/attribution is ungated, so the whole matrix runs back to back with every
transport seeing byte-identical params, headers and blob.  The only variable
is the transport; the FLIP / NOAUTH controls say whether the blob is being
verified at all.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)

import transport_fingerprint_test as T  # noqa: E402
import transport_test as tt  # noqa: E402

ORACLE = "2db6422f-0045-41bd-99ef-2264d70beec9"
REAL_TRACKER = "24xg6t54"


def q_of(row):
    ks = [k for k in row["order"] if k in row["claims"] and k not in T.CANON_ONLY]
    return "&".join("%s=%s" % (urllib.parse.quote(k, safe=""),
                               urllib.parse.quote(str(row["claims"][k]), safe=""))
                    for k in ks)


def read(st, txt):
    """-> (verdict, tracker_token, engagement_time)"""
    try:
        a = json.loads(txt).get("attribution", {})
    except Exception:
        return ("OTHER", "?", "?")
    ttok, eng = a.get("tracker_token"), str(a.get("engagement_time"))[:19]
    if ttok == REAL_TRACKER:
        return "PASS(RECOGNIZED)", ttok, eng
    if a.get("tracker_name") == "Organic":
        return "FAIL(Organic)", ttok, eng
    return "PASS(other-nonorganic)", ttok, eng


def main():
    rows = tt.parse_capture()
    attr = next(r for r in rows
                if r["kind"] == "attribution" and r["gps_adid"] == ORACLE)
    q = "/attribution?" + q_of(attr)
    blob = attr["blob_b64"]
    print("oracle identity %s   capture row %d   query %d B   blob %d B"
          % (ORACLE, attr["row"], len(q), len(__import__("base64").b64decode(blob))))
    print("expected on a verified signature: tracker_token=%s\n" % REAL_TRACKER)

    plan = [(t, d, fn, kw, attr["auth"], "genuine blob") for t, d, fn, kw in T.ARMS]
    plan += [
        ("FLIP", "CONTROL corrupted blob (byte0 bit0) + stdlib",
         T.send_httpclient, {}, T.flip_b64_of(blob), "corrupted blob"),
        ("FLIP-D", "CONTROL corrupted blob + DEVICE curl",
         T.send_device_curl, {}, T.flip_b64_of(blob), "corrupted blob"),
        ("NOAUTH", "CONTROL no Authorization + stdlib",
         T.send_httpclient, {}, None, "no auth"),
        ("NOAUTH-D", "CONTROL no Authorization + DEVICE curl",
         T.send_device_curl, {}, None, "no auth"),
    ]

    print("%-9s %-38s %-5s %-24s %-11s %s" %
          ("arm", "transport", "http", "verdict", "tracker", "engagement_time"))
    out = []
    for tag, desc, fn, kw, a, kind in plan:
        try:
            st, txt, el, enc = fn("GET", q, a, None, **kw)
        except Exception as e:
            st, txt, el, enc = 0, "%s: %s" % (type(e).__name__, e), 0.0, "-"
        v, ttok, eng = read(st, txt)
        out.append({"arm": tag, "transport": desc, "kind": kind, "status": st,
                    "verdict": v, "tracker_token": ttok, "engagement_time": eng,
                    "elapsed": round(el, 2), "body_sha": T.body_hash(txt),
                    "body": txt[:900]})
        print("%-9s %-38s %-5s %-24s %-11s %s" %
              (tag, desc[:38], st, v, ttok, eng))
        time.sleep(4)

    p = os.path.join(T.OUTDIR, "attr_matrix_results.json")
    json.dump(out, open(p, "w"), indent=1)
    gen = [r for r in out if r["kind"] == "genuine blob"]
    ctrl = [r for r in out if r["kind"] != "genuine blob"]
    print("\n== TRANSPORT VERDICT (genuine blob, oracle identity) ==")
    for r in gen:
        print("  %-9s %-38s HTTP %-4s %-24s tracker=%s"
              % (r["arm"], r["transport"][:38], r["status"], r["verdict"],
                 r["tracker_token"]))
    passed = [r["arm"] for r in gen if r["verdict"].startswith("PASS")]
    print("\n  PASSING TRANSPORTS: %s" % (passed or "NONE"))
    print("  CONTROLS:")
    for r in ctrl:
        print("    %-9s %-38s %-24s tracker=%s"
              % (r["arm"], r["transport"][:38], r["verdict"], r["tracker_token"]))
    if len({r["tracker_token"] for r in gen}) == 1:
        print("\n  >> all %d genuine transports agree on tracker_token=%s "
              "-> response is TRANSPORT-INDEPENDENT" % (len(gen), gen[0]["tracker_token"]))
    if ctrl and all(r["tracker_token"] != REAL_TRACKER for r in ctrl):
        print("  >> every control (corrupted blob / no auth) fell back to Organic "
              "-> the Authorization blob IS being verified")
    print("\nsaved", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
