"""Analyze the F(T) sweep: extract region words per T, test linearity."""
import json, struct, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
SEC0 = 1789240512
USEC0 = 500000

def T_of(cfg):
    # gettimeofday read #5 in the path: off = 4 ms of virtual clock
    us = cfg.get("usec", USEC0) + 4000
    sec = cfg.get("sec", SEC0) + us // 1000000
    return sec + us % 1000000

def region_of(tag):
    d = json.load(open(os.path.join(HERE, "fill_runs", tag + ".json")))
    ds = d["descs"][0]
    by = {e["build_idx"]: e for e in ds}
    d0 = struct.unpack(">36I", bytes.fromhex(by[0]["hex"]))
    d4 = struct.unpack(">8I", bytes.fromhex(by[4]["hex"]))
    d2 = struct.unpack(">I", bytes.fromhex(by[2]["hex"]))[0]
    return d0, d2, d4

def main():
    rows = []
    for tag in os.listdir(os.path.join(HERE, "fill_runs")):
        if not tag.endswith(".json") or tag == "emit_trace.json":
            continue
        name = tag[:-5]
        try:
            d = json.load(open(os.path.join(HERE, "fill_runs", tag)))
        except Exception:
            continue
        cfg = d["cfg"]
        try:
            d0, d2, d4 = region_of(name)
        except Exception:
            continue
        T = T_of(cfg)
        rows.append((T, name, d0, d2, d4))
    rows.sort()
    M = 1 << 32
    print("%-12s %10s  W0        X         T0        T1        T2        T3        d2        d4[6]" % ("run", "T"))
    for T, name, d0, d2, d4 in rows:
        print("%-12s %10d  %08x  %08x  %08x  %08x  %08x  %08x  %08x  %08x" % (
            name, T, d0[0], d0[1], d0[2], d0[3], d0[4], d0[5], d2, d4[6]))
    # linearity tests on W0 and d2 across consecutive sorted Ts
    print("\nlinearity (W0): for pairs (T1,T2),(T2,T3): slope equal?")
    ws = [(T, d0[0]) for T, name, d0, d2, d4 in rows]
    for i in range(len(ws) - 2):
        (t1, w1), (t2, w2), (t3, w3) = ws[i], ws[i+1], ws[i+2]
        if t2 == t1 or t3 == t2:
            continue
        s1 = (w2 - w1) * pow(t2 - t1, -1, M) % M if (t2 - t1) % 2 else None
        d1 = (w2 - w1) % M; d2_ = (w3 - w2) % M
        dt1, dt2 = t2 - t1, t3 - t2
        print("  %d->%d->%d: dW0/dT = %+d/%d, %+d/%d  (per-1: %.3f vs %.3f)" % (
            t1, t2, t3, d1 if d1 < 2**31 else d1 - M, dt1,
            d2_ if d2_ < 2**31 else d2_ - M, dt2,
            (d1 - M if d1 > 2**31 else d1) / dt1, (d2_ - M if d2_ > 2**31 else d2_) / dt2))

if __name__ == "__main__":
    main()
