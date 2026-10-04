# py_ladder2.py — the NOW-FAITHFUL recognition ladder (F.py region).
#
# Rebuilds py_ladder.py's recognition ladder EXACTLY — same genuine captured
# query, same already-consumed identity (gps_adid 0e789180-…, adid 06a7174d…),
# same signing second 1789474915, same 21-claim attribution law (#10 248/246 B),
# same transport/headers — and changes ONLY the blob source: mint_blob() with
# the F.py faithful region instead of the unfaithful region used before.
#
# Arms:
#   A0   genuine verbatim (control, expect 400 ask_in)
#   A1p  mint_blob, F region, V = fresh arbitrary 32-bit, pid=12345
#   A1pp mint_blob, F region, V = make_V(second, usec)  (fill_model)
#   A2   1-bit flip of A1p (control, expect 200)
#   A6   A1p with ONE region law broken (L1 U2^U0 off)
#
#   python py_ladder2.py            # offline: recon + mints + diffs
#   python py_ladder2.py --send     # + the live recognition ladder
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
import mint_pipeline as MP
from header_gen import make_header

UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
GEN_AUTH = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))
OUT = os.path.join(HERE, "py_ladder2_result.json")
RES = {}


def send(path, params, blob, auth=None, method="GET", ua=UA):
    auth = auth or MP.auth_header(blob)
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


def dwords_diff(a, b):
    return [i for i in range(48) if a[i * 4:i * 4 + 4] != b[i * 4:i * 4 + 4]]


def main():
    do_send = "--send" in sys.argv
    G = json.load(open(os.path.join(HERE, "fresh_genuine.json"), encoding="utf-8"))
    qs = G["query"].split("?", 1)[1]
    val = {k: v[0] for k, v in
           urllib.parse.parse_qs(qs, keep_blank_values=True).items()}
    blob_gen = bytes.fromhex(G["blob_hex"])
    second = 1789474915

    print("=== the genuine unit under test (SAME identity as py_ladder) ===")
    print("  gps=%s  created_at=%s  params=%d"
          % (val.get("gps_adid"), val.get("created_at"), len(val)))
    print("  blob %d B  header==make_header(%d): %s"
          % (len(blob_gen), second, blob_gen[:16] == make_header(second)))

    claims = MP.claims_from_wire(val, "attribution")
    padded, unp = MP.claims_for_law(claims, "attribution")
    print("  claims=%d keys  #10 padded=%d unpadded=%d (py_ladder parity)"
          % (len(claims), len(padded), unp))
    RES["identity"] = {"gps_adid": val.get("gps_adid"),
                       "second": second, "params": len(val),
                       "desc10_padded": len(padded), "desc10_unpadded": unp}

    # ---- A1p: F region, fresh arbitrary 32-bit V, pid 12345 ----
    V_p = 0xA1A1F00D
    t0 = time.time()
    blob_p, info_p = MP.mint_blob_ex(claims, second, V=V_p, pid=12345,
                                     tid=12346, kind="attribution")
    laws_p = MP.region_laws(info_p["d0"], info_p["d4"])

    # ---- A1pp: F region, V = make_V(second, usec) per fill_model ----
    V_pp = MP.make_V(second, 800000)   # tv_sec ^ tv_usec, usec ~ sent_at .810
    blob_pp, info_pp = MP.mint_blob_ex(claims, second, V=V_pp, pid=12345,
                                       tid=12346, kind="attribution")
    laws_pp = MP.region_laws(info_pp["d0"], info_pp["d4"])

    # ---- A6: A1p with ONE region law broken (L1 U2^U0 off) ----
    d0p, d2p, d4p = info_p["d0"], info_p["d2"], info_p["d4"]
    bad_d0 = b"".join(((0x00010000 + i) & 0xFFFFFFFF).to_bytes(4, "big")
                      for i in range(36))
    laws_6 = MP.region_laws(bad_d0, d4p)
    blob_6, info_6 = MP.mint_blob_ex(claims, second, V=V_p, pid=12345,
                                     tid=12346, kind="attribution",
                                     region=(bad_d0, d2p, d4p))

    # ---- A2: 1-bit flip of A1p ----
    flip = bytearray(blob_p)
    flip[-1] ^= 1
    flip = bytes(flip)

    def head(label, blob, info, laws, note):
        print("\n=== %s ===" % label)
        print("  status=%s steps=%d nrand=%d  blob=%d B  (%.1fs)"
              % (info["status"], info["steps"], info["nrand"], len(blob),
                 time.time() - t0))
        print("  header law OK: %s   V=0x%08x pid=%s"
              % (blob[:16] == make_header(second), info["V"], info["pid"]))
        print("  region laws: L1=%s L2=%s L3=%s"
              % (laws["L1_tile_Rrep"], laws["L2_d4_6_hi_eq_R"],
                 laws["L3_X_eq_U3"]))
        d = dwords_diff(blob, blob_gen)
        print("  vs genuine: equal=%s  differing=%d/48" % (blob == blob_gen, len(d)))
        return {"status": info["status"], "V": "0x%08x" % info["V"],
                "pid": info["pid"], "blob_len": len(blob),
                "header_ok": blob[:16] == make_header(second),
                "laws": laws, "vs_genuine_diff_dwords": len(d),
                "note": note}

    RES["mint"] = {
        "A1p": head("A1p  F region, V=fresh 0x%08x, pid=12345" % V_p,
                    blob_p, info_p, laws_p,
                    "faithful F.region, arbitrary V, plausible pid"),
        "A1pp": head("A1pp F region, V=make_V(second,800000)=0x%08x" % V_pp,
                     blob_pp, info_pp, laws_pp,
                     "faithful F.region, fill_model V"),
        "A6": head("A6   A1p with L1 broken (U2^U0 off)", blob_6, info_6,
                   laws_6, "A1p region with d0 tile law deliberately broken"),
    }
    RES["A2_flip_of_A1p_last_dword"] = flip[-1] ^ 1

    if not do_send:
        json.dump(RES, open(OUT, "w"), indent=1)
        print("\n(offline only - re-run with --send for the recognition ladder)")
        return 0

    # ---- the recognition ladder (live) ----
    arms = []

    def run(label, blob, note=""):
        code, body = send("/attribution", val, blob)
        print("  %-42s -> %-20s %s"
              % (label, tag(code), body.strip().replace("\r\n", "")[:70]))
        arms.append({"label": label, "http": code, "verdict": tag(code),
                     "body": body[:400], "note": note})
        time.sleep(2)
        return code

    print("\n=== RECOGNITION LADDER 2 (live, NOW-FAITHFUL region) ===")
    print("  oracle: 400 + ask_in:7200000 = RECOGNIZED ; 200 + wy7261z/Organic = NOT")
    run("A0 genuine verbatim (control)", blob_gen,
        "genuine blob + genuine query (expect 400)")
    run("A1p mint F region V=fresh pid=12345", blob_p,
        "KEY: faithful F.region, same claims+second")
    run("A1pp mint F region V=make_V(sec,usec)", blob_pp,
        "KEY: faithful F.region, fill_model V")
    run("A2 1-bit flip of A1p (control)", flip,
        "sanity: blob bytes matter (expect 200)")
    run("A6 A1p with L1 broken (U2^U0 off)", blob_6,
        "isolates: does server check region laws?")
    RES["arms"] = arms
    json.dump(RES, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
