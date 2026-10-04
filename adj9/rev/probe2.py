r"""probe2.py — full bodies for the genuine replays + unit-by-unit state.

probe1 (sig_probe.py) showed: byte-exact genuine blob -> 400 ask_in; ANY change
(1 bit in body, 1 bit in header, crafted body, fresh auid) -> 200 Organic.
Two questions remain:
  1. what exactly is the 400 message (throttle/duplicate, or a signature check)?
  2. does ANY genuine unit still answer VKM today (i.e. is there a live record
     to work against), or is the whole adid 2fedfd3d down to Organic?

Replays here are verbatim (blob from saz_sessions.json), so this is fast - no
minting.  Usage: python probe2.py
"""
import base64
import http.client
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

PACK = r"C:\Users\Apps\AppData\Local\Temp\opencode\vkm_replay_pack.json"
OUT = os.path.join(HERE, "probe2_result.json")
UNITS = [1, 2, 0, 1]          # 073ccff9 / 33b31aeb / 0ac8ea63 / 073ccff9 again


def send_raw(url, blob, ua):
    auth = ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())
    pr = urllib.parse.urlsplit(url)
    path = pr.path + ("?" + pr.query if pr.query else "")
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    conn.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth)
    conn.putheader("User-Agent", ua)
    conn.putheader("Host", pr.hostname)
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Accept-Encoding", "gzip")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


def main():
    pack = json.load(open(PACK))
    S = json.load(open(os.path.join(HERE, "saz_sessions.json")))
    runs = []
    for idx in UNITS:
        unit = pack[idx]
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(unit["url"]).query)
        auid, gps = q["android_uuid"][0], q["gps_adid"][0]
        blob = None
        for s in S:
            if (s.get("params", {}).get("android_uuid") == auid
                    and str(s.get("url", "")).endswith("/attribution")):
                blob = bytes.fromhex(s["sig_hex"])
        tag = "unit%d %s %s ib=%s" % (idx, auid[:8], gps[:8],
                                      q.get("initiated_by", ["?"])[0])
        if blob is None:
            print("[%s] no genuine /attribution blob found" % tag, flush=True)
            continue
        st, body = send_raw(unit["url"], blob, unit["headers"]["User-Agent"])
        print("[%s] HTTP %s\n    %s" % (tag, st, body[:500]), flush=True)
        runs.append({"unit": idx, "auid": auid, "gps": gps, "http": st,
                     "body": body[:800], "hdr": blob[:16].hex()})
        time.sleep(3)
    json.dump(runs, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()