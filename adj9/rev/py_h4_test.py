# py_h4_test.py - the campaign's CENTRAL hypothesis, tested against the server's
# own recognition oracle (rev/WALL_A_SLICE_111.md).
#
#   Hypothesis "H": the 32-byte #4 slot is the keystore MAC (wh4_records.mac_doFinal).
#   rev/WALL_A_SLICE_103.md refuted it only by "the captured H is not byte-identical
#   to the golden #4" - a comparison that assumes the paired HARVEST is correct.
#
# The oracle (rev/WALL_A_SLICE_99.md 8.1, re-calibrated in py_ladder.log):
#   HTTP 400 + ask_in:7200000 = the server RECOGNIZED the package
#   HTTP 200 + wy7261z/Organic = it did NOT
# py_ladder measured: claim-identical + second-identical re-mint with #4=captured
# STRUCTURED record -> 200. This script asks whether #4 = the real MAC -> 400.
#
#   python py_h4_test.py
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
OUT = os.path.join(HERE, "py_h4_result.json")


def send(params, blob, method="GET"):
    req = urllib.request.Request(
        "https://app.adjust.com/attribution?%s" % urllib.parse.urlencode(params),
        method=method)
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
    return "RECOGNIZED(400)" if c == 400 else (
        "not-recognized(200)" if c == 200 else "HTTP %s" % c)


def main():
    G = json.load(open(os.path.join(HERE, "fresh_genuine.json"), encoding="utf-8"))
    val = {k: v[0] for k, v in urllib.parse.parse_qs(
        G["query"].split("?", 1)[1], keep_blank_values=True).items()}
    blob_gen = bytes.fromhex(G["blob_hex"])
    second = 1789474915
    W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
    H = bytes.fromhex(W["mac_doFinal"][W["golden_nsign_idx"]]["hex"])
    print("golden H (mac_doFinal[%d]) = %s" % (W["golden_nsign_idx"], H.hex()))

    FILL = {"adj_signing_id": "1500000", "activity_kind": "attribution",
            "client_sdk": "android5.7.0", "headers_id": "10",
            "native_version": "5.0.0",
            "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"}
    val_att = dict(FILL)
    val_att.update(val)

    t0 = time.time()
    st, blob_h, desc, unp = F.make_signature_law(val_att, "attribution",
                                                  second=second, d4=H)
    print("mint #4=H : status=%s #10=%dB blob=%dB %.1fs"
          % (st, len(desc), len(blob_h), time.time() - t0))
    print("  header law OK: %s" % (blob_h[:16] == blob_gen[:16]))
    d = [i for i in range(48)
         if blob_h[i * 4:i * 4 + 4] != blob_gen[i * 4:i * 4 + 4]]
    print("  vs genuine blob: differing=%d/48" % len(d))

    res = {"H": H.hex(), "status": st, "desc10_len": len(desc)}
    for label, blob in (("CONTROL genuine verbatim", blob_gen),
                        ("OUR mint, #4 = the real MAC (H)", blob_h)):
        c, b = send(val, blob)
        print("  %-32s -> %-20s %s" % (label, tag(c),
                                       b.strip().replace("\r\n", "")[:90]))
        res[label] = {"http": c, "verdict": tag(c), "body": b[:300]}
        time.sleep(2)
    json.dump(res, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT)


if __name__ == "__main__":
    main()