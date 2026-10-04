"""repoll_attr.py — re-poll /attribution for a funneled identity several times.

The server answers ask_in=2000 (2 s). The click may join asynchronously after
the sdk_click is processed. Polls with a fresh attribution signing each time.
Usage: python repoll_attr.py <gps> <android_uuid> [polls] [gap_seconds]
"""
import base64
import http.client
import json
import os
import random
import struct
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_pipeline as M
import F as FP
import adj9_full_chain as AF

APP_TOKEN = "jut9tib0eeps"
CLIENT_SDK = "android5.7.0"
GEN_AUTH = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)"
WIN_HEAD = (0x2B, 0x48)


def mint_attribution_auth(gps, auid):
    val = {
        "app_token": APP_TOKEN, "gps_adid": gps, "android_uuid": auid,
        "activity_kind": "attribution", "initiated_by": "sdk",
        "environment": "production", "api_level": "31",
        "app_version": "3.14.0", "created_at": AF.fmt(int(time.time()), 77).decode(),
        "device_name": "moto g42", "device_type": "phone",
        "gps_adid_src": "service", "os_name": "android", "os_version": "12",
        "package_name": "com.penti.app", "tracking_enabled": "1",
        "client_sdk": CLIENT_SDK, "adj_signing_id": "1500000",
        "headers_id": "10", "native_version": "5.0.0",
        "adj_verification": GEN_AUTH,
    }
    sec = int(time.time())
    S = random.getrandbits(32)
    d0w, d2w, d4w = FP.region(S, 0, 0, head=WIN_HEAD)
    padded, unpadded = M.claims_for_law(val, "attribution")
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d2 = struct.pack(">I", d2w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    blob, info = M.finex_mint([by[i] for i in M.VA_ORDER], sec)
    print("  signed sec=%d st=%s" % (sec, info["status"]), flush=True)
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), GEN_AUTH))


def poll(gps, auid, auth):
    q = urllib.parse.urlencode({
        "app_token": APP_TOKEN, "gps_adid": gps, "android_uuid": auid,
        "activity_kind": "attribution", "initiated_by": "sdk",
        "needs_response_details": "1", "environment": "production",
    })
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    conn.putrequest("GET", "/attribution?" + q, skip_host=1,
                    skip_accept_encoding=1)
    for k, v in (("Client-SDK", CLIENT_SDK), ("Authorization", auth),
                 ("User-Agent", UA), ("Host", "app.adjust.com")):
        conn.putheader(k, v)
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", "replace")
    conn.close()
    return resp.status, body


def main():
    gps, auid = sys.argv[1], sys.argv[2]
    polls = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    gap = float(sys.argv[4]) if len(sys.argv) > 4 else 25.0
    out = []
    for i in range(polls):
        auth = mint_attribution_auth(gps, auid)
        code, body = poll(gps, auid, auth)
        net = "?"
        try:
            net = json.loads(body).get("attribution", {}).get("network", "?")
        except Exception:
            pass
        print("poll %d: %d net=%s %s" % (i + 1, code, net, body[:150]), flush=True)
        out.append({"poll": i + 1, "http": code, "network": net,
                    "body": body[:400]})
        if net and net != "Organic" and net != "?":
            print("*** JOINED: %s ***" % net, flush=True)
            break
        if i < polls - 1:
            time.sleep(gap)
    json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "repoll_result.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
