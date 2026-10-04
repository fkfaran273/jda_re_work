"""explore_mem.py — parse vm_mem region dumps, enumerate native stream structs,
validate LENQ semantics against logged workhorse x3 words, hunt the body."""
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DEV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "device")
PM = 0x0000FFFFFFFFFFFF

def load_regions():
    regs = []
    meta = json.load(open(os.path.join(DEV, "vm_mem", "meta.json")))
    for f in os.listdir(os.path.join(DEV, "vm_mem")):
        if f.startswith("R_") and f.endswith(".bin"):
            base = int(f[2:-4], 16)
            data = open(os.path.join(DEV, "vm_mem", f), "rb").read()
            regs.append((base, data))
    regs.sort()
    return regs

class Mem:
    def __init__(self, regs):
        self.regs = regs
    def inrange(self, va):
        va &= PM
        for b, d in self.regs:
            if b <= va < b + len(d):
                return True
        return False
    def u8(self, va):
        va &= PM
        for b, d in self.regs:
            if b <= va < b + len(d):
                return d[va - b]
        return None
    def u32(self, va):
        va &= PM
        for b, d in self.regs:
            if b <= va < b + len(d) - 3:
                o = va - b
                return struct.unpack_from("<I", d, o)[0]
        return None
    def u64(self, va):
        va &= PM
        for b, d in self.regs:
            if b <= va < b + len(d) - 7:
                o = va - b
                return struct.unpack_from("<Q", d, o)[0]
        return None

def untag(v):
    return v & PM if (v >> 56) else v

def parse_stream(m, va):
    va &= PM
    lim = m.u32(va)
    ofp = m.u64(va + 8)
    acc = m.u32(va + 0x10)
    cnt = m.u32(va + 0x14)
    dap = m.u64(va + 0x18)
    if lim is None or ofp is None or dap is None:
        return None
    ofp, dap = untag(ofp), untag(dap)
    return {"va": va, "limit": lim, "offs_ptr": ofp, "acc": acc,
            "count": cnt, "data_ptr": dap}

def stream_arrays(m, st, maxoff=4096):
    """read data (count elems) and offs (up to acc/limit) arrays"""
    cnt = st["count"]
    data = [m.u32(st["data_ptr"] + 4 * i) for i in range(min(cnt, 256))]
    n = min(st["acc"] if st["acc"] else maxoff, maxoff, st["limit"])
    offs = [m.u32(st["offs_ptr"] + 4 * i) for i in range(n)]
    return data, offs

def lenq_native(st, data, offs, n):
    if not data:
        return None
    top = data[-1]
    idx = (top + n) & 0xFFFFFFFF
    if idx < st["limit"] and idx < len(offs):
        return offs[idx]
    if idx < st["limit"]:
        return -1  # beyond dumped offs
    return 0

if __name__ == "__main__":
    m = Mem(load_regions())
    d = json.load(open(os.path.join(DEV, "vm_full.json")))
    wh = [h for h in d if h.get("tag") == "workhorse"]
    r1 = [h for h in wh if int(h["x1"], 16) <= 89 and int(h["n"]) < 110]
    logged = {}  # k -> value[k-1] emitted (x3 at iteration k)
    for h in r1:
        k = int(h["x1"], 16)
        logged[k] = int(h["x3"], 16) & 0xFFFFFFFF
    vals = [logged[k] for k in sorted(logged) if k >= 1]
    print("known values[0..88]:", len(vals))
    print("vals[0..5]:", " ".join("%08x" % v for v in vals[:6]))

    # 1. source stream round1
    SRC = 0x6e72aac1e0
    st = parse_stream(m, SRC)
    print("\nSRC stream:", st)
    if st:
        data, offs = stream_arrays(m, st)
        print("  data(bases):", ["%08x" % x if x is not None else "?" for x in data[:8]], "count", st["count"])
        print("  acc", st["acc"], "limit", st["limit"], "offs dumped", len(offs))
        ok = 0
        for k in range(min(89, len(offs))):
            v = lenq_native(st, data, offs, k)
            if v is not None and v == vals[k]:
                ok += 1
        print("  LENQ(k)==logged for k<%d: %d/%d" % (min(89, len(offs)), ok, min(89, len(offs))))
        print("  offs[0..8]:", " ".join("%08x" % x for x in offs[:9] if x is not None))

    # 2. enumerate all stream structs
    cands = []
    for b, dd in m.regs:
        for va in range(b, b + len(dd) - 0x20, 8):
            lim = struct.unpack_from("<I", dd, va - b)[0]
            if not (0 < lim <= 0x40000):
                continue
            acc = struct.unpack_from("<I", dd, va - b + 0x10)[0]
            cnt = struct.unpack_from("<I", dd, va - b + 0x14)[0]
            if cnt < 1 or cnt > 64 or acc > 0x40000:
                continue
            ofp = untag(struct.unpack_from("<Q", dd, va - b + 8)[0])
            dap = untag(struct.unpack_from("<Q", dd, va - b + 0x18)[0])
            if not m.inrange(ofp) or not m.inrange(dap):
                continue
            cands.append((va, lim, acc, cnt, ofp, dap))
    print("\nstream candidates:", len(cands))
    seen = set()
    for va, lim, acc, cnt, ofp, dap in cands:
        if va in seen:
            continue
        seen.add(va)
        st = parse_stream(m, va)
        data, offs = stream_arrays(m, st)
        top = data[-1] if data and data[0] is not None else None
        # ascii check
        asc = sum(1 for v in offs if v is not None and 0x20 <= (v >> 24) < 0x7f and 0x20 <= (v & 0xff) < 0x7f)
        print("  %08x lim=%6d acc=%6d cnt=%2d top=%s offsn=%d ascii=%d" %
              (va, lim, acc, cnt, "%08x" % top if top is not None else "?", len(offs), asc))
