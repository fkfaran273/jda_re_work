"""validate_body_decoder.py — corpus validation of body_decoder.py.

For each corpus row (known region + blob): measure the affine body map at the
row's (claims, second), decode the captured blob, compare the recovered
record against the KNOWN region (S at [20:24), head at [3:19)), reconstruct
the FULL region via F.py and remint — the remint must reproduce the capture
byte-exact (48/48 words).

Usage:  python validate_body_decoder.py [rows] [n_probes] [workers]
        rows default 7; "all" -> 0,1,4,5,6,7
"""
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from body_decoder import BodyDecoder, VA_ORDER, REC_N  # noqa: E402
import mint_pipeline as M                               # noqa: E402

ROWS = sys.argv[1] if len(sys.argv) > 1 else "7"
NPROBES = int(sys.argv[2]) if len(sys.argv) > 2 else 12
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 6
if ROWS == "all":
    ROWS = [0, 1, 4, 5, 6, 7]
else:
    ROWS = [int(x) for x in ROWS.split(",")]

D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

asg = json.load(open(os.path.join(HERE, "all_signings.json")))
ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))


def base_descs(row):
    """descs_base with placeholder region (probes replace d0/d2/d4)."""
    r = asg[row]
    descs_by = {
        0: (36, 0, b"\x00" * 144),
        9: (5, 0, D9),
        8: (4, 0, D8),
        4: (8, 0, b"\x00" * 32),
        2: (1, 0, b"\x00" * 4),
        7: (1, 0, bytes.fromhex(r["d7"])),
        10: (len(bytes.fromhex(r["d10"])) // 4, 0, bytes.fromhex(r["d10"])),
        5: (1, 0, bytes.fromhex(r["d5"]) if r.get("d5") else b"\x00" * 4),
        6: (1, 0, bytes.fromhex(r["d6"]) if r.get("d6") else b"\x00" * 4),
        1: (0, 0, b""),
        3: (0, 0, b""),
    }
    return [descs_by[i] for i in VA_ORDER]


def remint(descs, second):
    blob, info = M.finex_mint(descs, second, max_steps=60_000_000)
    return blob, info


def main():
    nok = 0
    for row in ROWS:
        second = ph3[row]["second"]
        cap = bytes.fromhex(ph3[row]["blob"])
        t0 = time.time()
        print("=== row %d second=%d ===" % (row, second), flush=True)
        dec = BodyDecoder(base_descs(row), second, n_probes=NPROBES,
                          workers=WORKERS)
        res = dec.decode(cap)
        print("  rank=%d inconsistent=%d consts_ok=%s insample_bad=%d"
              % (res["rank"], res["inconsistent"], res["consts_ok"],
                 dec.insample_bad))
        # known values
        d0cap = bytes.fromhex(asg[row]["d0"])
        d2w_cap = struct.unpack(">I", bytes.fromhex(asg[row]["d2"]))[0]
        seed_cap = int.from_bytes(bytes.fromhex(asg[row]["d2"]), "little")
        d0w_cap = struct.unpack(">36I", d0cap)
        head_exp = b"".join(struct.pack("<I",
                                        ((w & 0xFFFF) << 16) | (w >> 16))
                            for w in d0w_cap[:4])
        rec = res["record"]
        ok_s = rec[20:24] == struct.pack("<I", seed_cap)
        ok_head = rec[3:19] == head_exp
        print("  S     recovered %016x.. expected %08x  -> %s"
              % (res["seed"], seed_cap, "MATCH" if ok_s else "MISMATCH"))
        print("  head  recovered %s expected %s -> %s"
              % (res["head"], head_exp.hex(),
                 "MATCH" if ok_head else "MISMATCH"))
        reg = None
        remint_ok = False
        if ok_s and ok_head and res["consts_ok"] and not res["inconsistent"]:
            reg = dec.region_from(res)
            if reg is None:
                print("  region reconstruction: head phase NOT matched")
            else:
                d4cap = struct.unpack(">8I", bytes.fromhex(asg[row]["d4"]))
                d0ok = reg["d0"] == list(d0w_cap)
                d4ok = reg["d4"] == list(d4cap)
                d2ok = reg["d2"] == d2w_cap
                print("  region: phase=%s d0=%s d2=%s d4=%s"
                      % (reg["phase"],
                         "MATCH" if d0ok else "MISMATCH",
                         "MATCH" if d2ok else "MISMATCH",
                         "MATCH" if d4ok else "MISMATCH"))
                # remint with the reconstructed region
                d0b = b"".join(struct.pack(">I", w) for w in reg["d0"])
                d2b = struct.pack(">I", reg["d2"])
                d4b = b"".join(struct.pack(">I", w) for w in reg["d4"])
                r = asg[row]
                claims = bytes.fromhex(r["d10"])
                padded = claims + b"\x00" * (-len(claims) % 4)
                by = {0: (36, 0, d0b), 9: (5, 0, D9), 8: (4, 0, D8),
                      4: (8, 0, d4b), 2: (1, 0, d2b),
                      7: (1, 0, struct.pack(">I", len(claims))),
                      10: (len(padded) // 4, 0, padded),
                      5: (1, 0, bytes.fromhex(r["d5"]) if r.get("d5")
                          else b"\x00" * 4),
                      6: (1, 0, bytes.fromhex(r["d6"]) if r.get("d6")
                          else b"\x00" * 4),
                      1: (0, 0, b""), 3: (0, 0, b"")}
                descs = [by[i] for i in VA_ORDER]
                blob, info = remint(descs, second)
                nmatch = sum(1 for k in range(48)
                             if blob[4 * k:4 * k + 4] == cap[4 * k:4 * k + 4])
                remint_ok = blob == cap
                print("  remint: %d/48 words %s (%.0fs steps=%d)"
                      % (nmatch, "FULL MATCH" if remint_ok else "DIFF",
                         time.time() - t0, info["steps"]))
                if not remint_ok:
                    diff = [k for k in range(48)
                            if blob[4 * k:4 * k + 4] != cap[4 * k:4 * k + 4]]
                    print("   diff words:", diff[:20])
        nok += bool(ok_s and ok_head and res["consts_ok"]
                    and not res["inconsistent"] and reg and remint_ok)
        print("  elapsed %.0fs" % (time.time() - t0), flush=True)
    print("=== VALIDATION: %d/%d rows fully decoded+reminted ==="
          % (nok, len(ROWS)))


if __name__ == "__main__":
    main()
