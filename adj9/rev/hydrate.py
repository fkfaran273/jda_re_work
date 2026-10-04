"""hydrate.py — read-only hydration of vm_final.Ex from device/vm_mem region dumps.

FIXED vs previous revision (slice-77 follow-up):
  * parses FULL offs + data arrays from R_*.bin (the old code capped offs at
    200 entries and stopped at the first zero — live MAIN-class streams are
    far larger),
  * native stream struct layout verified against the binary:
      +0x00 limit (u32)   LENQ index bound
      +0x08 offs ptr      u64 -> VALUE array (LENQ reads offs[TOP+n])
      +0x10 acc (u32)     write cursor (EMIT merge sets acc = idx+1)
      +0x14 count (u32)   length of the DATA (frame-base) array
      +0x18 data ptr      u64 -> frame-base array; TOP = data[count-1]
    (derived from LENQ 0x147304 / OUTLEN 0x1472e8 / EMIT 0x146ed8 disassembly,
    see WALL_A_SLICE_78+; the old code swapped the roles)
  * MTE-tagged pointers (top byte 0xb4 etc.) are masked to 48 bits for
    LOOKUP only; raw memory is never rewritten,
  * hydrated streams are READ-ONLY: StreamObj.ro=True disables sync_struct,
    so stocked region memory inside ex.mem is never clobbered.

Never writes to device/vm_mem/*.bin or mutates the dumped bytes.
"""
import os, struct, json, glob

PM = 0x0000FFFFFFFFFFFF  # 48-bit VA; masks MTE/heap tags (0xb4xxxx...)


def untag(v):
    """Strip an MTE/heap tag from a pointer for lookup (never for storage)."""
    v &= (1 << 64) - 1
    return v & PM if (v >> 56) else v


class RegionMem:
    """Byte-accurate read-only view over the vm_mem R_*.bin dumps."""

    def __init__(self, dev_dir=None):
        if dev_dir is None:
            dev_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "..", "device", "vm_mem")
        self.regs = []  # (base, bytes)
        for f in sorted(os.listdir(dev_dir)):
            if f.startswith("R_") and f.endswith(".bin"):
                base = int(f[2:-4], 16)
                self.regs.append((base, open(os.path.join(dev_dir, f), "rb").read()))
        self.regs.sort()

    def inrange(self, va):
        va &= PM
        return any(b <= va < b + len(d) for b, d in self.regs)

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
                return struct.unpack_from("<I", d, va - b)[0]
        return None

    def u64(self, va):
        va &= PM
        for b, d in self.regs:
            if b <= va < b + len(d) - 7:
                return struct.unpack_from("<Q", d, va - b)[0]
        return None


def load_regions():
    return RegionMem()


def load_mem():
    """Flatten the dumps into a {addr: u64} dict suitable for Ex.mem.
    RAW values (no untagging) — pointer untagging happens at deref time
    (vm_final.ld/st/stream_for mask addresses with PM)."""
    mem = {}
    for base, data in load_regions().regs:
        for off in range(0, len(data) - 7, 8):
            v = struct.unpack_from("<Q", data, off)[0]
            if v:
                mem[base + off] = v
    return mem


def rd32(mem, va):
    """u32 read from an {addr: u64} mem dict (legacy helper)."""
    va &= PM
    a8 = va & ~7
    w = mem.get(a8, 0)
    return (w & 0xFFFFFFFF) if (va & 7) == 0 else (w >> 32) & 0xFFFFFFFF


def parse_stream(rm, va):
    """Parse the native stream struct at VA from the dumps. Returns dict or
    None if the header is not inside any dumped region."""
    va &= PM
    lim = rm.u32(va)
    ofp = rm.u64(va + 8)
    acc = rm.u32(va + 0x10)
    cnt = rm.u32(va + 0x14)
    dap = rm.u64(va + 0x18)
    if lim is None or ofp is None or acc is None or cnt is None or dap is None:
        return None
    return {"va": va, "limit": lim, "offs_ptr": untag(ofp), "acc": acc,
            "count": cnt, "data_ptr": untag(dap),
            "offs_tagged": (rm.u64(va + 8) >> 56) != 0,
            "data_tagged": (rm.u64(va + 0x18) >> 56) != 0}


def read_arrays(rm, st, hard_cap=1 << 20):
    """Read the FULL data (frame-base, count entries) and offs (value,
    acc/limit entries) arrays from the containing regions. No 200-entry cap.
    Entries whose bytes fall outside every dump read as None."""
    cnt = st["count"]
    data = []
    if 0 < cnt <= hard_cap:
        data = [rm.u32(st["data_ptr"] + 4 * i) for i in range(cnt)]
    n = min(max(st["acc"], st["limit"]), hard_cap) if (st["acc"] or st["limit"]) else 0
    offs = []
    if 0 < n <= hard_cap:
        offs = [rm.u32(st["offs_ptr"] + 4 * i) for i in range(n)]
    st["data_missing"] = sum(1 for v in data if v is None)
    st["offs_missing"] = sum(1 for v in offs if v is None)
    return data, offs


def hydrate(ex, rm, vas, verbose=True):
    """Hydrate vm_final streams for each VA from the dumps (READ-ONLY).

    Builds native-correct StreamObj state:
      s.data = frame-base array (count entries; TOP = data[-1])
      s.offs = value array    (FULL, uncapped; LENQ reads offs[TOP+n])
    ro=True => sync_struct is a no-op, so the stocked region words already
    present in ex.mem are never overwritten.  If an array extends past the
    dumped bytes the missing entries stay absent (LENQ falls back to 0,
    same as native's out-of-limit behaviour for our best knowledge).
    """
    got = []
    for va0 in vas:
        va = va0 & PM
        st = parse_stream(rm, va)
        if st is None:
            continue
        if st["count"] == 0 and st["acc"] == 0:
            if verbose:
                print("hydrate: %012x EMPTY at dump time (acc=0,count=0,limit=%d)"
                      % (va, st["limit"]))
            continue
        data, offs = read_arrays(rm, st)
        s = ex.stream_for(va)
        s.ro = True
        s.data = [0 if v is None else v for v in data]
        s.offs = [0 if v is None else v for v in offs] or [0]
        s._acc = st["acc"]
        if verbose:
            print("hydrate: %012x limit=%d acc=%d count=%d data=%d(%d miss) "
                  "offs=%d(%d miss) TOP=%08x"
                  % (va, st["limit"], st["acc"], st["count"], len(data),
                     st["data_missing"], len(offs), st["offs_missing"],
                     s.data[-1] if s.data else 0))
        got.append((va, st))
    return got


if __name__ == "__main__":
    rm = load_regions()
    print("regions:", ["%012x+%x" % (b, len(d)) for b, d in rm.regs])
    d = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "device", "vm_full.json")))
    wh = [h for h in d if h.get("tag") == "workhorse"]
    vas = set()
    for h in d:
        for k in ("x0", "x1", "x2", "x20"):
            try:
                vas.add(untag(int(h[k], 16)))
            except Exception:
                pass
    inr = [v for v in sorted(vas) if rm.inrange(v)]
    print("arg-derived VAs in dumps:", ["%012x" % v for v in inr])
    sys_path = os.path.dirname(os.path.abspath(__file__))
    import sys
    sys.path.insert(0, sys_path)
    from vm_final import Ex
    ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
    hydrate(ex, rm, inr)
