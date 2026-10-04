# py_region.py - WHICH BYTES OF THE BODY MUST BE GENUINE?
#
# py_ladder proved the server validates the 176-byte body: the genuine blob is
# recognized (400) and our law-consistent re-mint is not (200), with the query,
# claim values, second and Authorization header held identical. This script
# localises the required region by dword surgery - no minting, one send per arm:
#
#     G = genuine 48-dword blob (recognized)
#     M = our re-mint of the same payload (not recognized)
#     prefix(k) = G[0:k] ++ M[k:48]      -> how far must the genuine prefix run?
#     suffix(k) = M[0:k] ++ G[k:48]      -> how far must the genuine suffix run?
#
# If only the fully genuine blob is recognized, recognition is HOLISTIC (a stored
# artefact match). If a short prefix/suffix suffices, the required region is
# localised and that region is the computation we are missing.
#
#   python py_region.py
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_forge as F

UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))
OUT = os.path.join(HERE, "py_region_result.json")


def send(params, blob):
    req = urllib.request.Request(
        "https://app.adjust.com/attribution?%s" % urllib.parse.urlencode(params),
        method="GET")
    req.add_header("Client-SDK", "android5.7.0")
    req.add_header("Authorization", F.auth_header(blob))
    req.add_header("User-Agent", UA)
    req.add_header("Accept-Encoding", "identity")
    try:
        with DIRECT.open(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


def tag(c):
    return "RECOGNIZED" if c == 400 else ("not" if c == 200 else "HTTP%s" % c)


def dw(b):
    return [b[i * 4:i * 4 + 4] for i in range(48)]


def main():
    S = json.load(open(os.path.join(HERE, "py_mint_once.json"), encoding="utf-8"))
    G, M = dw(bytes.fromhex(S["genuine_hex"])), dw(bytes.fromhex(S["blob_hex"]))
    Gj = json.load(open(os.path.join(HERE, "fresh_genuine.json"), encoding="utf-8"))
    params = {k: v[0] for k, v in urllib.parse.parse_qs(
        Gj["query"].split("?", 1)[1], keep_blank_values=True).items()}
    print("dwords differing G vs M: %d/48 %s" % (len(S["diff"]), S["diff"]))
    arms = [("CONTROL genuine (k=48)", b"".join(G)),
            ("CONTROL ours (k=0)", b"".join(M))]
    for k in range(4, 48, 4):
        arms.append(("genuine prefix %2d" % k, b"".join(G[:k] + M[k:])))
    for k in range(4, 48, 4):
        arms.append(("genuine suffix %2d" % (48 - k), b"".join(M[:k] + G[k:])))
    res = []
    for label, blob in arms:
        c, b = send(params, blob)
        print("  %-22s -> %-11s %s" % (label, tag(c),
                                       b.strip().replace("\r\n", "")[:60]))
        res.append({"arm": label, "http": c, "verdict": tag(c)})
        time.sleep(2)
    json.dump(res, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT)


if __name__ == "__main__":
    main()