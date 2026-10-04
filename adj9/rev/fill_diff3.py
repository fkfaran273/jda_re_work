"""fill_diff3.py - stream-diff the two lift3 traces (fill_runs/lift3_V0.json vs
lift3_V1.json, 277 MB each) WITHOUT json.load: custom tokenizer over the flat
"writes" array ([gic, pc, addr, size, value] records) and the trailing "trace"
array ([gic, pc, 32 regs]).  Reports the first divergence (the V-entry) and
saves lift3_diff.json.
"""
import itertools
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = os.path.join(HERE, "fill_runs")

TOK = re.compile(rb"\d+|\[|\]")


def stream_ints(path, marker, depth0=1, chunk=1 << 22):
    """Yield the integers of the flat array that follows `marker`.
    depth0=1: after the marker the outer '[' is consumed; a '[' opens a record,
    the matching ']' closes it; the final ']' (depth back to 0) ends the array.
    """
    with open(path, "rb") as f:
        inside = False
        depth = depth0
        tail = b""
        while True:
            chunk_b = f.read(chunk)
            if not chunk_b:
                return
            data = tail + chunk_b
            if not inside:
                i = data.find(marker)
                if i < 0:
                    tail = data[-len(marker):]
                    continue
                data = data[i + len(marker):]
                inside = True
            j = data.rfind(b"]")
            if j < 0:
                tail = data
                continue
            tail = data[j + 1:]
            data = data[:j + 1]
            for m in TOK.finditer(data):
                t = m.group(0)
                if t == b"[":
                    depth += 1
                elif t == b"]":
                    depth -= 1
                    if depth == 0:
                        return
                else:
                    yield int(t)


def grouped(gen, n):
    it = iter(gen)
    while True:
        row = list(itertools.islice(it, n))
        if not row:
            return
        if len(row) != n:
            raise ValueError("ragged record at group end: %d" % len(row))
        yield row


def diff_writes(p0, p1, max_report=24):
    g0 = grouped(stream_ints(p0, b'"writes": ['), 5)
    g1 = grouped(stream_ints(p1, b'"writes": ['), 5)
    n = same = 0
    first = []
    pcs = {}
    addr_first = None
    for a, b in zip(g0, g1):
        n += 1
        if a == b:
            same += 1
            continue
        d = (a[4] ^ b[4], a[2], a[1])
        pcs[a[1]] = pcs.get(a[1], 0) + 1
        if len(first) < max_report:
            if addr_first is None:
                addr_first = a[2]
            first.append({"i": n, "gic": a[0], "pc": a[1], "addr": a[2],
                          "size": a[3], "v0": a[4], "v1": b[4],
                          "xor": a[4] ^ b[4], "sub": (b[4] - a[4]) & (2**64 - 1)})
    extra0 = sum(1 for _ in g0)
    extra1 = sum(1 for _ in g1)
    return {"n": n, "same": same, "ndiff": n - same, "first": first,
            "pcs": pcs, "extra0": extra0, "extra1": extra1}


def diff_trace(p0, p1, max_report=8):
    g0 = grouped(stream_ints(p0, b'"trace": ['), 34)
    g1 = grouped(stream_ints(p1, b'"trace": ['), 34)
    n = 0
    first = []
    for a, b in zip(g0, g1):
        n += 1
        if a == b:
            continue
        regs = [(i, a[2 + i], b[2 + i], (a[2 + i] ^ b[2 + i]))
                for i in range(32) if a[2 + i] != b[2 + i]]
        first.append({"i": n, "gic": a[0], "pc": a[1], "regs": regs})
        if len(first) >= max_report:
            break
    return {"n": n, "first": first}


def slice_trace(path, gic_lo, gic_hi):
    """records with gic in [gic_lo, gic_hi] (streaming)."""
    out = []
    for rec in grouped(stream_ints(path, b'"trace": ['), 34):
        if rec[0] > gic_hi:
            break
        if rec[0] >= gic_lo:
            out.append(rec)
    return out


def slice_writes(path, gic_lo, gic_hi):
    out = []
    for rec in grouped(stream_ints(path, b'"writes": ['), 5):
        if rec[0] > gic_hi:
            break
        if rec[0] >= gic_lo:
            out.append(rec)
    return out


if __name__ == "__main__":
    t0 = time.time()
    p0 = os.path.join(RUNS, "lift3_V0.json")
    p1 = os.path.join(RUNS, "lift3_V1.json")
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    res = {}
    if mode in ("all", "writes"):
        print("diffing writes...", flush=True)
        res["writes"] = diff_writes(p0, p1)
        w = res["writes"]
        print("records %d  same %d  DIFF %d  extra0 %d extra1 %d  (%.0fs)"
              % (w["n"], w["same"], w["ndiff"], w["extra0"], w["extra1"],
                 time.time() - t0))
        print("first diff pcs:", {hex(k): v for k, v in w["pcs"].items()})
        for f in w["first"][:12]:
            print("  i=%d gic=%d pc=0x%x addr=0x%x sz=%d v0=0x%016x v1=0x%016x xor=0x%016x"
                  % (f["i"], f["gic"], f["pc"], f["addr"], f["size"],
                     f["v0"], f["v1"], f["xor"]))
    if mode in ("all", "trace"):
        print("diffing trace...", flush=True)
        res["trace"] = diff_trace(p0, p1)
        for f in res["trace"]["first"]:
            print("TRACE first diff i=%d gic=%d pc=0x%x"
                  % (f["i"], f["gic"], f["pc"]))
            for (ri, v0, v1, x) in f["regs"]:
                print("   x%-2d  V0=0x%016x  V1=0x%016x  xor=0x%016x"
                      % (ri, v0, v1, x))
    out = os.path.join(HERE, "lift3_diff.json")
    json.dump(res, open(out, "w"), indent=1)
    print("saved", out, "%.0fs" % (time.time() - t0))
