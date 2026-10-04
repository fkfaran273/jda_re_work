"""_val_genuine.py — VM-validate the desc10_58 law against the matched
signing pairs in genuine_signings.json (adj9_cap_full.log capture):
rebuild the #10 claims with the law, decode the genuine blob, rebuild the
descriptor plane, drive the FinEx VM, and diff the minted blob vs genuine."""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))          # rev/ (fin_vm2, F, ...)
sys.path.insert(0, HERE)
import desc10_58 as LAW
from testbed import decode, region_parts, run_vm, build_descs

GS = os.path.join(HERE, "genuine_signings.json")


def main():
    data = json.load(open(GS, encoding="utf-8"))
    pairs = data["pairs"]
    print("matched pairs in genuine_signings.json: %d" % len(pairs))
    all_ok = True
    for i, p in enumerate(pairs):
        sign = p["sign"]
        kind = sign["map"].get("activity_kind", "session")
        second = p["nsig_ts"] // 1000
        blob = bytes.fromhex(p["nsig"])
        val = sign["map"]

        raw = LAW.build_desc10_58(val, kind)
        print("\n=== pair %d: %s  second=%d  claims_len=%d  claims_sha=%s"
              % (i, kind, second, len(raw),
                 __import__("hashlib").sha256(raw).hexdigest()[:16] + "..."))

        t0 = time.time()
        dec = decode(blob)
        d0, d4, d2, pfx = region_parts(dec, second)
        print("    head phase solved: %s  (%.1fs)"
              % (list(pfx) if pfx else None, time.time() - t0))

        t0 = time.time()
        mint, status = run_vm(second,
                              build_descs(second, raw, d0, d4, d2),
                              max_steps=60_000_000)
        dt = time.time() - t0
        if mint is None:
            print("    VM: NO SINK (status=%s)  %.1fs" % (status, dt))
            all_ok = False
            continue
        ndiff = sum(1 for j in range(192) if mint[j] != blob[j])
        orec = __import__("whiten_decoder").whiten_body_inverse(
            mint[16:160], mint[:16])
        blk_ok = orec[46:78] == dec["block"]
        exact = ndiff == 0
        print("    VM mint: %d/192 bytes match  block=%s  (%.1fs, status=%s)"
              % (192 - ndiff, "ok" if blk_ok else "X", dt, status))
        if not exact:
            pos = [j for j in range(192) if mint[j] != blob[j]]
            runs = []
            for j in pos:
                if runs and j == runs[-1][1] + 1:
                    runs[-1][1] = j
                else:
                    runs.append([j, j])
            print("    DIFF positions: %s" % pos)
            print("    DIFF runs: %s"
                  % ["%d-%d" % (a, b) for a, b in runs])
            print("    genuine: %s" % blob.hex())
            print("    minted : %s" % mint.hex())
        else:
            print("    BYTE-EXACT ***")
        all_ok &= exact
    print("\nRESULT:", "ALL BYTE-EXACT" if all_ok else "MISMATCHES REMAIN")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
