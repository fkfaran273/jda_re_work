#!/usr/bin/env python3
r"""transport_control_test.py — the two controls the 20-minute session gate
would otherwise hide.

The battery in transport_fingerprint_test.py can only ever obtain ONE clean
(non-gated) /session verdict per identity, so transport and blob-sensitivity
cannot both be judged from it.  These probes use a SECOND, stale identity
(2db6422f, last session 2026-09-24) so they are not gated, and they answer the
two questions that matter:

  CTRL-1  flipped blob, DEVICE transport (D) on /session
          -> a clean 200 + adid proves BOTH that the device transport gets a
             clean accepted session AND that /session does not verify the
             signature at all (the blob is irrelevant).

  CTRL-2  genuine blob, curl_cffi chrome131 (B) on /click, same identity
          -> a clean 200 + adid proves a NON-stdlib transport also gets a
             clean accepted request, so A is not special.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)

import transport_fingerprint_test as T  # noqa: E402
import transport_test as tt  # noqa: E402

CANON_ONLY = T.CANON_ONLY
STALE = "2db6422f-0045-41bd-99ef-2264d70beec9"


def q_of(row):
    ks = [k for k in row["order"] if k in row["claims"] and k not in CANON_ONLY]
    return "&".join("%s=%s" % (urllib.parse.quote(k, safe=""),
                               urllib.parse.quote(str(row["claims"][k]), safe=""))
                    for k in ks)


def shot(label, method, path, body, auth, fn, **kw):
    try:
        st, txt, el, enc = fn(method, path, auth, body, **kw)
    except Exception as e:
        print("%-10s EXC %s: %s" % (label, type(e).__name__, e))
        return None
    v, key = T.classify(st, txt)
    print("%-10s HTTP %-4s %5.2fs  %-34s %s" % (label, st, el, v, key[:95]))
    print("           body: %s" % txt[:400])
    return {"label": label, "status": st, "verdict": v, "key": key, "body": txt[:900]}


def main():
    rows = tt.parse_capture()
    by = {(r["kind"], r["gps_adid"]): r for r in rows}
    sess = by[("session", STALE)]
    click = by[("click", STALE)]
    print("stale identity %s" % STALE)
    print("  session row %d created=%s  click row %d created=%s\n"
          % (sess["row"], sess["created_at"], click["row"], click["created_at"]))

    out = []
    # CTRL-1: corrupted blob on the device's own stack
    print("--- CTRL-1  FLIPPED blob, DEVICE curl, POST /session ---")
    out.append(shot("CTRL-1", "POST", "/session", q_of(sess),
                    T.flip_b64_of(sess["blob_b64"]), T.send_device_curl))
    time_sleep = __import__("time")
    time_sleep.sleep(8)
    # CTRL-2: genuine blob, curl_cffi chrome131, POST /click
    print("\n--- CTRL-2  GENUINE blob, curl_cffi chrome131, POST /click ---")
    out.append(shot("CTRL-2", "POST", "/click", q_of(click), click["auth"],
                    lambda m, p, a, b: T.send_curl_cffi(m, p, a, b, "chrome131")))
    time_sleep.sleep(8)
    # CTRL-3: genuine blob, tls_client okhttp4_android_11, POST /attribution
    #         (the sharpest recognized/unrecognized read, and ungated)
    attr = by[("attribution", STALE)]
    print("\n--- CTRL-3  GENUINE blob, tls_client okhttp4_android_11, GET /attribution ---")
    out.append(shot("CTRL-3", "GET", "/attribution?" + q_of(attr), None, attr["auth"],
                    lambda m, p, a, b: T.send_tls_client(m, p, a, b, "okhttp4_android_11")))
    time_sleep.sleep(8)
    # CTRL-4: NOAUTH on the same attribution (device transport) — signature-free
    print("\n--- CTRL-4  NO Authorization, DEVICE curl, GET /attribution ---")
    out.append(shot("CTRL-4", "GET", "/attribution?" + q_of(attr), None, None,
                    T.send_device_curl))

    p = os.path.join(T.OUTDIR, "control_results.json")
    json.dump([o for o in out if o], open(p, "w"), indent=1)
    print("\n== CONTROL SUMMARY ==")
    for o in out:
        if o:
            print("  %-8s HTTP %-4s %-34s %s" % (o["label"], o["status"],
                                                 o["verdict"], o["key"][:60]))
    print("\nsaved", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
