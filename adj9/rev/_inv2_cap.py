"""_inv2_cap.py — instrumented forward capture for the vm_inverse2 work.

Runs FinEx on a corpus row with FULL wire logging (E/Q on every stream with
32-bit values, PUSH/POP on every queue with values, CAP swaps) and dumps:

  meta   : row, second, status, steps, region bytes (d0/d2/d4), blob
  wire   : the full wire op list (kinds E/Q/PUSH/POP/SW/PU)
  record : raw record bytes (builder writes, pc 0x119538, MAIN [1134..1278))

Usage:
  python _inv2_cap.py 7 real  _inv2_row7_real.json.gz
  python _inv2_cap.py 7 rand  _inv2_row7_rand.json.gz   (random region)
"""
import gzip
import json
import random
import struct
import sys
import time

HERE = "."
sys.path.insert(0, ".")
from fin_vm2 import FinEx                                  # noqa: E402
import F as FREG                                           # noqa: E402

MAIN = 0x5450001000
SINK = 0x5500000000
M48 = 0xFFFFFFFFFFFF
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
REC_TOP = 1134
REC_N = 144
REC_BUILDER_PC = 0x119538


def corpus_descs(row, region=None):
    asg = json.load(open("all_signings.json", encoding="utf-8"))
    r = asg[row]
    if region is None:
        d0 = bytes.fromhex(r["d0"])
        d2 = bytes.fromhex(r["d2"])
        d4 = bytes.fromhex(r["d4"])
    else:
        d0, d2, d4 = region
    by = {0: (36, 0, d0),
          9: (5, 0, D9),
          8: (4, 0, D8),
          4: (8, 0, d4),
          2: (1, 0, d2),
          7: (1, 0, bytes.fromhex(r["d7"])),
          10: (len(bytes.fromhex(r["d10"])) // 4, 0, bytes.fromhex(r["d10"])),
          5: (1, 0, bytes.fromhex(r["d5"]) if r.get("d5") else b"\x00" * 4),
          6: (1, 0, bytes.fromhex(r["d6"]) if r.get("d6") else b"\x00" * 4),
          1: (0, 0, b""),
          3: (0, 0, b"")}
    return [by[i] for i in VA_ORDER]


def region_bytes(d0w, d2w, d4w):
    return (b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in d0w),
            struct.pack(">I", d2w & 0xFFFFFFFF),
            b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in d4w))


def run_row(row, region=None, max_steps=60_000_000):
    """One instrumented run.  region=None -> the row's REAL region."""
    asg = json.load(open("all_signings.json", encoding="utf-8"))
    ph3 = json.load(open("pair_h3.json", encoding="utf-8"))
    r = asg[row]
    if region is None:
        d0b = bytes.fromhex(r["d0"])
        d2b = bytes.fromhex(r["d2"])
        d4b = bytes.fromhex(r["d4"])
    else:
        d0b, d2b, d4b = region_bytes(*region)
    descs = corpus_descs(row, (d0b, d2b, d4b))
    second = int(ph3[row]["second"])

    ex = FinEx(second, descs)
    ex.__dict__["_wire_log"] = []
    t0 = time.time()
    st = ex.run(max_steps=max_steps)
    dt = time.time() - t0

    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & M48, n)] = v & 0xFFFFFFFF
    blob = b"".join(struct.pack(">I", last.get((SINK, k), 0)) for k in range(48))

    rec = {}
    for ev in ex.__dict__["_wire_log"]:
        if ev[0] == "E" and ev[1] == REC_BUILDER_PC:
            o = (ev[3] + ev[4]) & M48
            if REC_TOP <= o < REC_TOP + REC_N and (o - REC_TOP) not in rec:
                rec[o - REC_TOP] = ev[5] & 0xFF
    record = bytes(rec.get(i, 0) for i in range(REC_N))

    wire = []
    for e in ex.__dict__["_wire_log"]:
        e = list(e)
        if e[0] in ("E", "Q"):
            e[2] &= M48
            for j in (3, 4, 5):
                e[j] &= 0xFFFFFFFF
        else:
            e[2] &= M48
            e[3] &= 0xFFFFFFFF
        wire.append(tuple(e))
    return {"row": row, "second": second, "status": st, "steps": ex.steps,
            "nrand": ex.nrand, "secs": round(dt, 1),
            "d0": d0b.hex(), "d2": d2b.hex(), "d4": d4b.hex(),
            "blob": blob.hex(), "record": record.hex(), "wire": wire}


def rand_region(rng):
    V = rng.getrandbits(31)
    pid = rng.randrange(1, 0x8000)
    d4w = FREG._d4_words(V)
    d0w = FREG._d0_words(d4w, head=FREG.HEAD_FIRST)
    return d0w, V, d4w


def main():
    row = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    mode = sys.argv[2] if len(sys.argv) > 2 else "real"
    out = sys.argv[3] if len(sys.argv) > 3 else ("_inv2_row%d_%s.json.gz"
                                                 % (row, mode))
    if mode == "real":
        res = run_row(row)
    else:
        rng = random.Random(int(mode) if mode.isdigit() else 0x5EED2)
        res = run_row(row, region=rand_region(rng))
    tgt = bytes.fromhex(json.load(open("pair_h3.json"))[row]["blob"]) \
        if mode == "real" else None
    if tgt is not None:
        print("blob match vs capture:", res["blob"] == tgt.hex())
    print("status=%s steps=%d nrand=%d %.0fs record=%s.."
          % (res["status"], res["steps"], res["nrand"], res["secs"],
             res["record"][:24]))
    with gzip.open(out, "wt") as f:
        json.dump(res, f)
    print("saved", out)


if __name__ == "__main__":
    main()
