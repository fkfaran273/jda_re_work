r"""sig_probe.py — is the /attribution verdict sensitive to the SIGNATURE blob?

Ground truth: vkm_replay_pack unit #1 (auid 073ccff9, gps d016e7e4,
created_at 2026-09-14T17:53:11.322Z+0530, initiated_by=backend) answered
"200 VKM 24pxw9rl" on 14-09 17:53 and was stable for hours (TODAY.md §2).
Genuine 192-B blob = saz_sessions.json session 3 sig_hex.

The wire dump also shows the SAME record flipping VKM->Organic->VKM on the real
device (15-09 00:41-00:52), so every variant is bracketed by the verbatim
baseline in the same run — otherwise a server-side Organic window masquerades as
a content effect (that is the flaw in TODAY.md §3's 1-bit-flip claim).

  A  verbatim genuine blob               D  genuine hdr[0:16] + crafted body
  B  verbatim + FRESH android_uuid       E  crafted hdr[0:16] + genuine body
  C  crafted blob, identical claims      F  genuine + 1 bit flipped body[0]
                                         G  genuine + 1 bit flipped hdr[0]

Usage: python sig_probe.py
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
import adj9_full_chain as fc

PACK = r"C:\Users\Apps\AppData\Local\Temp\opencode\vkm_replay_pack.json"
UNIT = 1                      # index into the pack: the 17:53 backend request
ORIG_SEC = 1789388591         # header seed law second of that request
ORIG_CREATED = b"2026-09-14T17:53:11.322Z+0530"
ORIG_INSTALLED = b"2026-09-14T17:52:12.431Z+0530"
OUT = os.path.join(HERE, "sig_probe_result.json")

# the genuine /attribution body of this install is the moto g42 identity
fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"


def send_raw(url, blob, ua=None):
    """GET the URL byte-verbatim; only the Authorization header is supplied."""
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
    conn.putheader("User-Agent", ua or fc.UA)
    conn.putheader("Host", pr.hostname)
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Accept-Encoding", "gzip")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


def verdict(status, body):
    try:
        a = json.loads(body)["attribution"]
        return "%s / eng=%s" % (a.get("tracker_token"), a.get("engagement_time"))
    except Exception:
        return "HTTP %s %s" % (status, body[:80])


def genuine_blob():
    S = json.load(open(os.path.join(HERE, "saz_sessions.json")))
    unit = json.load(open(PACK))[UNIT]
    auid = urllib.parse.parse_qs(
        urllib.parse.urlsplit(unit["url"]).query)["android_uuid"][0]
    for s in S:
        if (s.get("params", {}).get("android_uuid") == auid
                and str(s.get("url", "")).endswith("/attribution")):
            return bytes.fromhex(s["sig_hex"]), unit, auid
    raise SystemExit("genuine /attribution blob for that auid not found")


def main():
    g, unit, auid = genuine_blob()
    url, gps = unit["url"], urllib.parse.parse_qs(
        urllib.parse.urlsplit(unit["url"]).query)["gps_adid"][0]
    print("unit#%d auid=%s gps=%s" % (UNIT, auid, gps), flush=True)
    print("genuine blob len=%d hdr=%s" % (len(g), g[:16].hex()), flush=True)

    st, n, crafted = fc.make_signature(ORIG_SEC, ORIG_CREATED, gps, auid,
                                       ORIG_INSTALLED)
    print("crafted mint %s steps=%s\n  hdr=%s (same second => same header)"
          % (st, n, crafted[:16].hex()), flush=True)
    hdr_same = crafted[:16] == g[:16]
    print("crafted header == genuine header: %s" % hdr_same, flush=True)

    flip_body = bytearray(g); flip_body[16] ^= 0x01      # 1 bit in body[0]
    flip_hdr = bytearray(g);  flip_hdr[0] ^= 0x01        # 1 bit in header[0]
    hybrid_d = g[:16] + crafted[16:]                     # genuine hdr + ours
    hybrid_e = crafted[:16] + g[16:]                     # ours hdr + genuine
    fresh = auid[:-12] + "%012x" % (int(time.time()) & 0xffffffffffff)

    order = [
        ("A  verbatim genuine", g, url, "A"),
        ("C  crafted blob same claims", crafted, url, "C"),
        ("A  verbatim genuine", g, url, "A"),
        ("D  genuine hdr + crafted body", bytes(hybrid_d), url, "D"),
        ("A  verbatim genuine", g, url, "A"),
        ("E  crafted hdr + genuine body", bytes(hybrid_e), url, "E"),
        ("A  verbatim genuine", g, url, "A"),
        ("F  genuine + body[0] bit flip", bytes(flip_body), url, "F"),
        ("A  verbatim genuine", g, url, "A"),
        ("G  genuine + hdr[0] bit flip", bytes(flip_hdr), url, "G"),
        ("A  verbatim genuine", g, url, "A"),
        ("B  verbatim + fresh auid", g,
         url.replace(auid, fresh), "B"),
    ]
    res = {"unit": UNIT, "gps": gps, "auid": auid,
           "crafted_header_equals_genuine": hdr_same, "runs": []}
    for label, blob, u, tag in order:
        try:
            s, b = send_raw(u, blob)
            v = verdict(s, b)
        except Exception as e:
            s, v = "ERR", "%s: %s" % (type(e).__name__, e)
        print("%-34s -> %s %s" % (label, s, v), flush=True)
        res["runs"].append({"tag": tag, "label": label, "http": s,
                            "verdict": v})
        time.sleep(2)
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()