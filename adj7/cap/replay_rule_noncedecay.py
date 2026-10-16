"""replay_rule_noncedecay.py -- the user's challenge, probed directly.

Claim under test: "attribution verdicts do not change over time (proved on
adj8 + adj9) -- the payruki_again capture must still answer its logged
verdict 248wk8ym / VL-Alliance."

The adj7 law measured on 2026-10-07 (cap/FINAL_REPLAY_TEST.md ss4):
the stored verdict is keyed to the 12-B NONCE of the earning ask
(record a/d slots); an unseen nonce re-evaluates (Organic after the
window).  Probes c/e/f proved OUR mint with the DEVICE nonce returns
BOOKED with fresh second/header/claims/blob-bytes.

This probe re-fires exactly that shape today:
  N1  our mint, DEVICE nonce12 (fresh second, blob never sent)  -- decay test
  N2  our mint, FRESH nonce12                                    -- re-eval control
PASS (user's model) = N1 still returns VL-Alliance today.
"""
import gzip
import http.client
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
import adj7_pure as S                      # noqa: E402

RAW = os.path.join(HERE, "payruki_again", "raw")
ATTR_F = os.path.join(RAW, "43_c.txt")
DEVICE_NONCE = bytes.fromhex("bd37db0dc2162ab78b8dc5db")
LOGGED = {"tracker_token": "248wk8ym", "network": "VL-Alliance",
          "adid": "bc620c16d8112216e33514e30a03eb37"}
CAMPAIGN = {"cert_sha1": "c1bfafcaffb84b805288b985fbe48e7f33d2c6df",
            "adj_signing_id": "1300000", "headers_id": "8",
            "native_version": "3.62.0"}
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"


def load_request(path):
    t = open(path, "rb").read().decode("utf-8", "replace").replace("\r\n", "\n")
    head, _, _ = t.partition("\n\n")
    lines = head.split("\n")
    headers = {}
    for ln in lines[1:]:
        if not ln.strip() or ":" not in ln:
            break
        k, v = ln.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return lines[0], headers


def send(target, auth, client_sdk):
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest("GET", target, skip_host=1, skip_accept_encoding=1)
        c.putheader("Client-SDK", client_sdk)
        c.putheader("Authorization", auth)
        c.putheader("User-Agent", UA)
        c.putheader("Host", "app.adjust.com")
        c.putheader("Accept-Encoding", "gzip")
        c.endheaders()
        r = c.getresponse()
        raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return r.status, raw.decode("utf-8", "replace")
    finally:
        c.close()


def main():
    reqline, hdr = load_request(ATTR_F)
    target = reqline.split(" ")[1]
    query = target.split("?", 1)[1]
    params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    client_sdk = hdr.get("client-sdk", "android5.6.0")
    claims = S.build_claims("attribution", params, client_sdk=client_sdk,
                            include_block2=True)
    cert40 = CAMPAIGN["cert_sha1"].upper().encode()

    out = {}
    for name, nonce in (("N1_our_mint_DEVICE_nonce", DEVICE_NONCE),
                        ("N2_our_mint_FRESH_nonce", None)):
        blob = S.sign(int(time.time()), nonce or os.urandom(12), claims, cert40)
        auth = ('Signature signature="%s",adj_signing_id="%s",algorithm="adj7",'
                'headers_id="%s",native_version="%s"'
                % (blob.hex().upper(), CAMPAIGN["adj_signing_id"],
                   CAMPAIGN["headers_id"], CAMPAIGN["native_version"]))
        st, body = send(target, auth, client_sdk)
        try:
            j = json.loads(body)
            att = j.get("attribution") or {}
        except Exception:
            att = {}
        verdict = {"tracker_token": att.get("tracker_token"),
                   "network": att.get("network"),
                   "engagement_time": att.get("engagement_time"),
                   "installed_at": att.get("installed_at")}
        logged = (verdict["tracker_token"] == LOGGED["tracker_token"]
                  and verdict["network"] == LOGGED["network"])
        print("%s -> HTTP %d  %s" % (name, st, json.dumps(j)[:220]))
        print("   LOGGED-VERDICT-REPRODUCED: %s" % logged)
        out[name] = {"http": st, "body": body, "logged": logged}

    json.dump(out, open(os.path.join(HERE, "replay_rule_noncedecay_result.json"),
                        "w"), indent=1)
    n1 = out["N1_our_mint_DEVICE_nonce"]["logged"]
    print("\nVERDICT:", "row persists -- user model CONFIRMED (N1 booked)"
          if n1 else "N1 not booked today (row state moved / law changed)")


if __name__ == "__main__":
    main()
