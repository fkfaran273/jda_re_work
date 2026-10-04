"""hunt_kb.py — memory-write provenance tracing of the FinEx VM to find how
KB (240 B = 15x16-B round keys of the whitening SPN) is generated.

Phase trace : run ONE known-good signing (PENTI_CORPUS) with a logging mem
              dict recording (step, pc, addr, value) for every store.
Phase find  : locate KB (and T, cross-check) bytes in the write log; cluster
              hits by address; report the pc ranges that materialize them.
Phase window: dump the bytecode (mnemonics) around the KB-writing pcs.

Run:  python hunt_kb.py trace        # ~2-4 min, writes trace_pc.pkl
      python hunt_kb.py find         # search log for KB/T patterns
      python hunt_kb.py window A B   # dump bytecode pcs A..B (hex ok)
      python hunt_kb.py all          # trace + find
"""
import sys, os, time, struct, pickle, re
from array import array

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "C:/Users/Apps/Downloads/com.penti.app/adj9sign")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "pure_signer"))
import signer_simple as sg
from corpus_pc import PENTI_CORPUS
from pure_sign import KB as KB_REF, T as T_REF  # closed-form references

TRACE_PKL = os.path.join(HERE, "trace_pc.pkl")


def build_descs(claims_raw, d0, d4, d2, cert):
    padded = claims_raw + b"\x00" * (-len(claims_raw) % 4)
    by = {0: (36, 0, d0),
          9: (5, 0, cert), 8: (4, 0, bytes.fromhex("bffffffffffffd1f0007000000000000")),
          4: (8, 0, d4),
          2: (1, 0, d2),
          7: (1, 0, struct.pack(">I", len(claims_raw))),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, b"\x00\x00\x00\x00"),
          6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in sg.VA_ORDER]


class LogMem(dict):
    """mem dict that records (step, pc, addr, value) of every store."""
    __slots__ = ("ex", "stps", "spc", "sad", "sva")

    def __init__(self, ex):
        super().__init__()
        self.ex = ex
        self.stps = array("I")   # step index
        self.spc = array("I")    # pc of storing instruction
        self.sad = array("Q")    # address key
        self.sva = array("Q")    # stored value

    def __setitem__(self, k, v):
        self.stps.append(self.ex.steps)
        self.spc.append(self.ex.pc & 0xFFFFFFFF)
        self.sad.append(k)
        self.sva.append(v & 0xFFFFFFFFFFFFFFFF)
        dict.__setitem__(self, k, v)

    def __delitem__(self, k):
        dict.__delitem__(self, k)


def phase_trace(max_steps=60_000_000):
    pc = PENTI_CORPUS
    descs = build_descs(bytes.fromhex(pc["d10"])[:pc["unpadded"]],
                        bytes.fromhex(pc["d0"]), bytes.fromhex(pc["d4"]),
                        bytes.fromhex(pc["d2"]), bytes.fromhex(pc["d9"]))
    ex = sg.FinEx(int(pc["second"]), descs)
    lm = LogMem(ex)
    lm.update(ex.mem)          # keep the initialized VM state
    ex.mem = lm
    t0 = time.time()
    status = ex.run(max_steps=max_steps)
    t1 = time.time()
    # assemble blob like finex_mint does and verify byte-exactness
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    stream = None
    hdr = struct.unpack(">4I", __import__("signer_simple").make_header(int(pc["second"])))
    if sg.SINK in bys and tuple(bys[sg.SINK].get(k, 0) for k in range(4)) == hdr:
        stream = sg.SINK
    else:
        for sva in sorted(bys):
            if tuple(bys[sva].get(k, 0) for k in range(4)) == hdr:
                stream = sva
                break
    blob = b"".join(struct.pack(">I", bys[stream].get(k, 0)) for k in range(sg.BLOB_WORDS)) \
        if stream is not None else b""
    good = blob == bytes.fromhex(pc["blob_hex"])
    print("steps=%d status=%s stores=%d time=%.1fs blob-exact=%s"
          % (ex.steps, status, len(lm.sva), t1 - t0, good))
    assert good, "trace run did not reproduce the gold blob — aborting"
    with open(TRACE_PKL, "wb") as f:
        pickle.dump({"steps": ex.steps, "stps": lm.stps, "spc": lm.spc,
                     "sad": lm.sad, "sva": lm.sva,
                     "final_mem": dict(lm)}, f, protocol=4)
    print("saved", TRACE_PKL, os.path.getsize(TRACE_PKL), "bytes")


# ---------------------------------------------------------------- find ----

def _pattern_map(pairs):
    """value -> [(name, off, width, endian)] for every byte-shifted window."""
    m = {}
    for name, blob in pairs:
        for w, tag in ((8, "q"), (4, "d")):
            for off in range(0, len(blob) - w + 1):
                for end in ("little", "big"):
                    v = int.from_bytes(blob[off:off + w], end)
                    m.setdefault(v, []).append((name, off, w, end))
    return m


def phase_find():
    with open(TRACE_PKL, "rb") as f:
        d = pickle.load(f)
    sva, sad, spc, stps = d["sva"], d["sad"], d["spc"], d["stps"]
    print("stores=%d steps=%d" % (len(sva), d["steps"]))
    kb55 = bytes(v ^ 0x55 for v in KB_REF)
    t55 = bytes(v ^ 0x55 for v in T_REF)
    pm_kb = _pattern_map([("KB", KB_REF), ("KB^55", kb55)])
    pm_t = _pattern_map([("T", T_REF), ("T^55", t55)])

    def scan(pm, label):
        hits = {}
        for i in range(len(sva)):
            v = sva[i]
            meta = pm.get(v)
            if meta:
                hits[i] = meta
        print("== %s: %d raw value hits" % (label, len(hits)))
        # cluster by address
        clusters = {}
        for i, metas in hits.items():
            a = sad[i]
            clusters.setdefault(a, []).append((i, metas))
        # merge adjacent addresses into regions
        addrs = sorted(clusters)
        regions = []
        for a in addrs:
            if regions and a <= regions[-1][1] + 8:
                regions[-1][1] = a
                regions[-1][2].extend(clusters[a])
            else:
                regions.append([a, a, list(clusters[a])])
        for a0, a1, items in regions:
            idxs = [i for i, _ in items]
            pcs = {}
            for i in idxs:
                pcs[spc[i]] = pcs.get(spc[i], 0) + 1
            name = items[0][1][0][0] if items and items[0][1] else "?"
            print("region %012x-%012x  n=%d  steps %d..%d  name~%s"
                  % (a0, a1, len(items), stps[min(idxs)], stps[max(idxs)], name))
            top = sorted(pcs.items(), key=lambda kv: -kv[1])[:10]
            print("   pcs:", " ".join("%x:%d" % (p, c) for p, c in top))
            # order of first appearance per offset
            offs = {}
            for i, metas in items:
                for (nm, off, w, end) in metas:
                    if nm in ("KB", "KB^55", "T", "T^55") and end == "little":
                        k = off
                        if k not in offs or stps[i] < offs[k][0]:
                            offs[k] = (stps[i], i, w)
            seq = sorted(offs.items())
            print("   first-appearance by offset:",
                  [(o, s, w) for o, (s, i, w) in seq[:24]], "..."
                  if len(seq) > 24 else "")
        return hits

    scan(pm_kb, "KB")
    scan(pm_t, "T")

    # also: scan the FINAL memory image for KB/T byte patterns
    fm = d["final_mem"]
    print("== final mem image: %d slots" % len(fm))
    for name, ref in (("KB", KB_REF), ("KB^55", bytes(v ^ 0x55 for v in KB_REF)),
                      ("T", T_REF)):
        found = []
        for a, v in fm.items():
            if v > (1 << 32):
                bys = v.to_bytes(8, "little")
                width = 8
            else:
                bys = v.to_bytes(4, "little")
                width = 4
            for off in range(0, len(ref) - width + 1):
                if bys == ref[off:off + width]:
                    found.append((a, off, width))
                    break
        if found:
            found.sort()
            print("  %s in final image at addrs:" % name,
                  ["%x(off=%d,w=%d)" % f for f in found[:40]],
                  "..." if len(found) > 40 else "")


def phase_window(a, b):
    def hx(x):
        return int(x, 16) if isinstance(x, str) else x
    a, b = hx(a), hx(b)
    n = 0
    for i in sg.INS:
        if a <= i.address <= b:
            print("%08x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
            n += 1
    print("(%d instructions)" % n)


# ---------------------------------------------------------- trace2 -------
# KB/T are never stored in mem -> instrument the queue/stream channel.

class TracedFinStream(sg.FinStream):
    __slots__ = ("ex",)
    def __init__(self, va, ex):
        super().__init__(va)
        self.ex = ex
    def emit(self, n, v):
        idx = super().emit(n, v)   # resolved absolute idx
        self.ex.elog.append((self.ex.pc, self.va & 0xFFFFFFFFFFFF,
                             idx & 0xFFFFFFFF, v & 0xFFFFFFFF))
        return idx
    def lenq(self, n):
        r = super().lenq(n)
        # resolve absolute idx the same way lenq does: top[-1] + n
        absi = (self.top[-1] + (n & 0xFFFFFFFF)) & 0xFFFFFFFF
        self.ex.llog.append((self.ex.pc, self.va & 0xFFFFFFFFFFFF,
                             absi, r))
        return r


def phase_trace2(max_steps=60_000_000):
    pc = PENTI_CORPUS
    descs = build_descs(bytes.fromhex(pc["d10"])[:pc["unpadded"]],
                        bytes.fromhex(pc["d0"]), bytes.fromhex(pc["d4"]),
                        bytes.fromhex(pc["d2"]), bytes.fromhex(pc["d9"]))
    ex = sg.FinEx(int(pc["second"]), descs)
    ex.qlog = []   # (kind, pc, qva, val)  kind in PUSH,POP,CPUSH,CSWAP
    ex.elog = []   # (pc, sva, n, v)      stream emits
    ex.llog = []   # (pc, sva, n, ret)    stream lenq reads

    orig_stream_for = ex.stream_for
    def stream_for(va):
        va &= sg.PM if hasattr(sg, "PM") else 0xFFFFFFFFFFFF
        s = ex.streams.get(va)
        if s is None or not isinstance(s, TracedFinStream):
            t = TracedFinStream(va, ex)
            if s is not None:
                t.top, t.offs, t.acc, t.limit = s.top, s.offs, s.acc, s.limit
            ex.streams[va] = t
            return t
        return s
    ex.stream_for = stream_for

    orig_qnodes = ex._q_nodes
    def qnodes(qva):
        q = ex.queues.get(qva)
        if q is None:
            q = []
            ex.queues[qva] = q
        return q
    ex._q_nodes = qnodes

    orig_push = ex.cap_push
    def cap_push(qva, k):
        q = ex.queues.setdefault(qva, [])
        if len(q) > k:
            ex.qlog.append(("CPUSH", ex.pc, qva & 0xFFFFFFFFFFFF, q[k]))
        return orig_push(qva, k)
    ex.cap_push = cap_push
    orig_swap = ex.cap_swap
    def cap_swap(qva, k):
        q = ex.queues.setdefault(qva, [])
        if len(q) > k:
            ex.qlog.append(("CSWAP", ex.pc, qva & 0xFFFFFFFFFFFF, q[k]))
        return orig_swap(qva, k)
    ex.cap_swap = cap_swap

    # hook the queue PUSH/POP inside run(): run() uses
    # self.queues.setdefault(qva, []).insert/pop directly -> replace
    # ex.queues with a dict subclass returning monitored QLists.
    class QList(list):
        __slots__ = ("qva",)
        def insert(self, i, v):
            ex.qlog.append(("PUSH", ex.pc, self.qva, v & 0xFFFFFFFF))
            list.insert(self, i, v & 0xFFFFFFFF)
        def pop(self, i=0):
            v = list.pop(self, i)
            ex.qlog.append(("POP", ex.pc, self.qva, v & 0xFFFFFFFF))
            return v

    class QDict(dict):
        def _mk(self, qva):
            q = dict.get(self, qva)
            if q is None:
                q = QList()
                q.qva = qva & 0xFFFFFFFFFFFF
                dict.__setitem__(self, qva, q)
            return q
        def setdefault(self, qva, default=None):
            return self._mk(qva)
        def get(self, qva, d=None):
            return self._mk(qva)

    ex.queues = QDict(ex.queues)
    for qva, q in ex.queues.items():
        nq = QList(q)
        nq.qva = qva & 0xFFFFFFFFFFFF
        dict.__setitem__(ex.queues, qva, nq)

    t0 = time.time()
    status = ex.run(max_steps=max_steps)
    t1 = time.time()
    print("steps=%d status=%d time=%.1fs qops=%d emits=%d lenqs=%d"
          % (ex.steps, status if isinstance(status, int) else -1, t1 - t0,
             len(ex.qlog), len(ex.elog), len(ex.llog)))
    # verify blob
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    hdr = struct.unpack(">4I", sg.make_header(int(pc["second"])))
    stream = None
    if sg.SINK in bys and tuple(bys[sg.SINK].get(k, 0) for k in range(4)) == hdr:
        stream = sg.SINK
    else:
        for sva in sorted(bys):
            if tuple(bys[sva].get(k, 0) for k in range(4)) == hdr:
                stream = sva
                break
    blob = b"".join(struct.pack(">I", bys[stream].get(k, 0))
                    for k in range(sg.BLOB_WORDS)) if stream else b""
    print("blob-exact=%s" % (blob == bytes.fromhex(pc["blob_hex"])))
    out = {"qops": ex.qlog, "emits": ex.elog, "lenqs": ex.llog,
           "queues": {k & 0xFFFFFFFFFFFF: list(v) for k, v in ex.queues.items()},
           "streams": {va & 0xFFFFFFFFFFFF: dict(s.offs)
                       for va, s in ex.streams.items()},
           "steps": ex.steps}
    with open(os.path.join(HERE, "trace_q.pkl"), "wb") as f:
        pickle.dump(out, f, protocol=4)
    print("saved trace_q.pkl")


def phase_find2():
    with open(os.path.join(HERE, "trace_q.pkl"), "rb") as f:
        d = pickle.load(f)
    kb55 = bytes(v ^ 0x55 for v in KB_REF)

    def find_bytes_in(vals, label):
        """vals: list of 32-bit values; interpret as LE or BE byte stream."""
        for end in ("little", "big"):
            bys = b"".join(v.to_bytes(4, end) for v in vals)
            for name, ref in (("KB", KB_REF), ("KB^55", kb55)):
                off = bys.find(ref)
                if off >= 0:
                    print("  %s: %s FOUND at byte %d (%s, dword-aligned=%s)"
                          % (label, name, off, end, off % 4 == 0))
                    return True
        return False

    print("== queues (final contents)")
    for qva, q in sorted(d["queues"].items()):
        if q:
            find_bytes_in(q, "queue %x (len %d)" % (qva, len(q)))
    print("== streams (offs content by idx)")
    for sva, offs in sorted(d["streams"].items()):
        if not offs:
            continue
        idxs = sorted(offs)
        dense = all(idxs[i] == idxs[0] + i for i in range(min(len(idxs), 64)))
        vals = [offs[i] for i in idxs]
        hit = find_bytes_in(vals, "stream %x (n=%d dense=%d)"
                           % (sva, len(idxs), dense))
        if not hit:
            # per-index single dword match
            for i in idxs:
                v = offs[i]
                for end in ("little", "big"):
                    b4 = v.to_bytes(4, end)
                    if b4 in KB_REF or b4 in kb55:
                        print("  stream %x idx %d = %08x matches KB dword (%s)"
                              % (sva, i, v, end))
                        break
    print("== lenq reads matching KB dwords")
    n = 0
    for (p, sva, idx, ret) in d["lenqs"]:
        for end in ("little", "big"):
            b4 = ret.to_bytes(4, end)
            if b4 in KB_REF or b4 in kb55:
                print("  pc=%x stream=%x idx=%d ret=%08x (%s)"
                      % (p, sva, idx, ret, end))
                n += 1
                break
        if n > 60:
            print("  ...")
            break
    print("== qop values matching KB dwords (first 40)")
    n = 0
    for (kind, p, qva, val) in d["qops"]:
        for end in ("little", "big"):
            b4 = val.to_bytes(4, end)
            if b4 in KB_REF or b4 in kb55:
                print("  %s pc=%x q=%x val=%08x (%s)" % (kind, p, qva, val, end))
                n += 1
                break
        if n > 40:
            print("  ...")
            break


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd in ("trace", "all"):
        phase_trace()
    if cmd in ("find", "all"):
        phase_find()
    if cmd in ("trace2",):
        phase_trace2()
    if cmd in ("find2",):
        phase_find2()
    if cmd == "window":
        phase_window(sys.argv[2], sys.argv[3])
