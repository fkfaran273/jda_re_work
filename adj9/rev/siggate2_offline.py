"""siggate2_offline.py — round-2 offline checks (no network).

1. Winning M4 SAZ blobs: which second does the 16-B header encode, relative to
   the body's created_at?  (The app's sign-vs-stamp offset.)
2. pair_h3 device captures: nsign wall time vs header second (sign latency).
3. How stale were OUR arms?  Measure a live-path session mint end-to-end
   (exactly the api_session_mint mint path, minus the network) and time it.
   Arms stamped created_at == header second == now-2 (MINT_SKEW) at mint START,
   so at server receipt the declared times were (2 + mint_seconds) stale.
4. Region structural laws (L1/L2/L3) on a LIVE-path F.py region (what our arms
   actually shipped) across several seconds/pids.
5. F.py composition: seed-recovery sanity (d2 -> seed) on captured regions.
"""
import base64
import datetime
import json
import os
import re
import struct
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from header_gen import make_header
import mint_pipeline as M
import F as FMOD


def hdr_offset(path):
    b = open(path, encoding="utf-8", errors="replace").read()
    blob = base64.b64decode(re.search(r'signature="([^"]+)"', b).group(1))
    hdr = blob[:16]
    ca = urllib.parse.unquote(re.search(r"created_at=([^&]+)", b).group(1))
    dt = datetime.datetime.strptime(ca, "%Y-%m-%dT%H:%M:%S.%fZ%z")
    sec = int(dt.timestamp())
    hits = [s - sec for s in range(sec - 30, sec + 31) if make_header(s) == hdr]
    return ca, sec, hits


def main():
    print("=== 1. M4 winning blobs: header-second minus created_at-second ===")
    for i, kind in ((1, "session"), (2, "sdk_click"), (3, "attribution")):
        ca, sec, hits = hdr_offset(os.path.join(
            HERE, "_saz_x", "raw", "%d_c.txt" % i))
        print("  %-11s created_at=%s  header_off=%s" % (kind, ca, hits))

    print("\n=== 2. pair_h3 device captures: nsign wall vs header second ===")
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    for i, r in enumerate(ph3):
        ts = r.get("nsign_ts")
        if ts:
            print("  row %d: header_second=%d nsign_ts=%d (nsign - hdr = %+.3fs)"
                  % (i, r["second"], ts, ts / 1000.0 - r["second"]))

    print("\n=== 3. live-path mint duration (what made our arms stale) ===")
    val = M.synthetic_claims("session", int(time.time()))
    t0 = time.time()
    sec = int(time.time())
    V = M.make_V(sec)
    blob, info = M.mint_blob_ex(val, sec, V=V, kind="session")
    dt = time.time() - t0
    print("  mint_blob_ex(session): %.1fs  steps=%d nrand=%d status=%s"
          % (dt, info["steps"], info["nrand"], info["status"]))
    print("  => arm staleness model: created_at/header were %d + %.0f = ~%.0fs "
          "old at server receipt" % (2, dt, 2 + dt))

    print("\n=== 4. region laws on LIVE-path F.py regions ===")
    ok_all = True
    l3_fails = 0
    tested = 0
    for pid in (M.DEFAULT_PID, 12345, 26530):
        for sec in (1789239390, int(time.time())):
            V = M.make_V(sec)
            d0b, d2b, d4b = M.resolve_region(V, pid, M.DEFAULT_TID, None)
            laws = M.region_laws(d0b, d4b)
            tested += 1
            l3_fails += 0 if laws["L3_X_eq_U3"] else 1
            ok = laws["L1_tile_Rrep"] and laws["L2_d4_6_hi_eq_R"]
            ok_all &= ok
            print("  pid=%-6d sec=%d L1=%s L2=%s L3=%s hits=%s"
                  % (pid, sec, laws["L1_tile_Rrep"],
                     laws["L2_d4_6_hi_eq_R"], laws["L3_X_eq_U3"],
                     laws["L1_hits"][:3]))
    print("  L1+L2 on all live regions: %s ; L3 fails %d/%d"
          % (("PASS" if ok_all else "FAIL"), l3_fails, tested))

    print("\n=== 5. captured-region seed recovery (d2 -> seed -> F.py repro) ===")
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    for i in (0, 1, 4, 5, 6, 7):
        r = asg[i]
        d2 = bytes.fromhex(r["d2"])
        seed = int.from_bytes(d2, "little")
        d0, d2b, d4 = FMOD.region(seed & 0xFFFFFFFF, 0)  # pid folded in seed
        ok = (struct.pack(">I", d2b).hex() == r["d2"])
        print("  row %d: seed=0x%08x  d2 roundtrip=%s" % (i, seed, ok))


if __name__ == "__main__":
    main()
