"""_lineage.py - value-lineage tracer over fin_vm2.FinEx.

For every concrete 32-bit value produced during a run, record the instruction
that produced it and the concrete values of its inputs.  Result: a provenance
DAG keyed by concrete value.  Leaves are the descriptor-plane words (the
unknown region), read either by a plain `ldr` from a descriptor data window or
by the VM helper 0x147304 (LOAD).
"""
import json
import re
import struct
import sys
from collections import deque

sys.path.insert(0, ".")
from fin_vm2 import FinEx, FinStream
from vm_final import INS, IDX

M32 = 0xFFFFFFFF
DESC_BASE = 0x5700000000
DESC_STRIDE = 0x1000
NREG = re.compile(r"^[wx]\d+$")
SINK = 0x5500000000

OP_PUSH, OP_POP = 0x147630, 0x147734
OP_PUSH2, OP_POP2 = 0x146470, 0x146478
OP_EMIT, OP_LENQ, OP_OUTLEN = 0x146ed8, 0x147304, 0x1472e8
OP_RAND = 0x148d10
BL_HELPERS = {OP_PUSH, OP_PUSH2, OP_POP, OP_POP2, OP_EMIT, OP_LENQ,
              OP_OUTLEN, OP_RAND, 0x147120, 0x147220, 0x147a20, 0x14784c,
              0x147a18, 0x146558, 0x146650, 0x146474}


def _memop(o, m):
    """-> (dests, srcs, meminfo) with meminfo = (kind, base, off, reg)"""
    o = o.replace(" ", "")
    mm = re.match(r"^([A-Za-z0-9_.]+),\[([^\]]+)\](!?)$", o)
    if not mm:
        return None
    d, inner, wb = mm.group(1), mm.group(2), mm.group(3)
    # post-index:  d,[base],#imm
    mm2 = re.match(r"^([A-Za-z0-9_.]+),\[([A-Za-z0-9]+)\],#(-?[\dxa-f]+)$", o)
    if mm2:
        d, base, imm = mm2.group(1), mm2.group(2), int(mm2.group(3), 0)
        return [d], [], ("mem", base, imm, d, "post")
    parts = inner.split(",")
    base = parts[0]
    off = 0
    if len(parts) == 2:
        p2 = parts[1]
        if p2.startswith("#"):
            off = int(p2[1:], 0)
        else:
            off = ("idx", p2)
    elif len(parts) >= 3:
        off = ("idx", parts[1])
    kind = "store" if m.startswith("st") else "load"
    if not NREG.match(d):
        return [], [], ("mem", base, off, None, kind)
    if kind == "store":
        return [], [d], ("mem", base, off, d, kind)
    return [d], [], ("mem", base, off, d, kind)


def parse(pc):
    i = INS[IDX[pc]]
    m, o = i.mnemonic, i.op_str
    if m in ("b", "br", "blr", "ret", "nop", "cbz", "cbnz", "tbz", "tbnz"):
        return (m, [], [], None)
    if m == "bl":
        t = None
        try:
            t = int(o.strip().lstrip("#"), 0)
        except Exception:
            t = None
        if t in BL_HELPERS:
            if t in (OP_POP, OP_POP2):
                return ("POP", ["w0"], [], ("pop",))
            if t == OP_LENQ:
                return ("LENQ", ["w0"], [], ("lenq",))
            if t == OP_RAND:
                return ("RAND", ["w0"], [], ("rand",))
            if t in (OP_PUSH, OP_PUSH2):
                return ("PUSH", [], ["w2"], ("push",))
        return ("bl", [], [], None)
    if m in ("ldr", "ldur", "str", "stur", "ldrb", "strb", "ldrsh", "ldrh",
             "ldrsb", "ldrsw", "ldursw", "ldp", "stp", "ldpsw"):
        if m in ("ldp", "stp", "ldpsw"):
            o2 = o.replace(" ", "")
            mm = re.match(r"^([A-Za-z0-9_.]+),([A-Za-z0-9_.]+),\[([^\]]+)\]!?$", o2)
            if not mm:
                return (m, [], [], None)
            d1, d2, inner = mm.group(1), mm.group(2), mm.group(3)
            parts = inner.split(",")
            base = parts[0]
            off = int(parts[1][1:], 0) if len(parts) > 1 and parts[1].startswith("#") else 0
            if m == "stp":
                return (m, [], [d1, d2], ("mem2", base, off, (d1, d2), "store"))
            return (m, [d1, d2], [], ("mem2", base, off, (d1, d2), "load"))
        r = _memop(o, m)
        if r is None:
            return (m, [], [], None)
        dests, srcs, memi = r
        return (m, dests, srcs, memi)
    if m in ("cmp", "cmn", "tst", "ccmp", "ccmn"):
        p = o.split(",")
        return (m, [], [x.strip() for x in p if NREG.match(x.strip())], None)
    p = [x.strip() for x in o.split(",")]
    d = p[0] if p else ""
    dests = [d] if NREG.match(d) else []
    srcs = [x for x in p[1:] if NREG.match(x)]
    return (m, dests, srcs, None)


class Lineage:
    def __init__(self, ex):
        self.ex = ex
        self.prov = {}
        self.leaves = {}
        self.cache = {}
        self.pending = None
        self.unparsed = set()

    def reg(self, name):
        R = self.ex.R
        if NREG.match(name):
            return R.get("w" + name[1:], 0) & M32
        return 0

    def hook(self, ex=None):
        ex = ex if ex is not None else self.ex
        p = self.pending
        if p is not None:
            kind, dests, srcs, memi, snap, pcall, lv = p
            parents = []
            for d in dests:
                v = self.reg(d)
                if v in lv:
                    self.leaves.setdefault(v, lv[v])
                for tag, val in snap:
                    if tag == "L":
                        parents.append(("L",) + val)
                    elif val != v:      # drop identity copies (mov w3,w3)
                        parents.append(("V", val))
                self.prov[v] = (pcall, tuple(parents))
        pc = ex.pc
        info = self.cache.get(pc)
        if info is None:
            info = parse(pc)
            self.cache[pc] = info
        kind, dests, srcs, memi = info
        snap = []
        lv = {}
        R = ex.R
        if memi is None:
            for s in srcs:
                snap.append(("V", self.reg(s)))
        elif memi[0] == "pop":
            q = ex.queues.get(R.get("x1", 0) & 0xFFFFFFFFFFFF, [])
            snap.append(("V", (q[0] if q else 0) & M32))
        elif memi[0] == "lenq":
            s = ex.stream_for(R.get("x0", 0))
            snap.append(("V", s.lenq(R.get("w1", 0)) & M32))
        elif memi[0] == "rand":
            snap.append(("V", 0))
        elif memi[0] == "push":
            snap.append(("V", self.reg("w2")))
        elif memi[0] in ("mem", "mem2"):
            _, base, off, regs, kind2 = memi
            bv = R.get(base, 0)
            addrs = []
            if isinstance(off, tuple):
                iv = R.get(off[1], 0) & M32
                b0 = (bv + iv) & (2**64 - 1)
            else:
                b0 = (bv + off) & (2**64 - 1)
            addrs.append(b0 & ~7)
            if memi[0] == "mem2":
                addrs.append((b0 + 8) & ~7)
            for a in addrs:
                dseg = (a - DESC_BASE) // DESC_STRIDE
                drem = (a - DESC_BASE) % DESC_STRIDE
                if 0 <= dseg < 11 and drem % 4 == 0 and drem // 4 < 128:
                    lv[ex.mem.get(a, 0) & M32] = (dseg, drem // 4)
                snap.append(("V", ex.mem.get(a, 0) & M32))
        for s in srcs:
            if memi is None or memi[0] not in ("mem", "mem2"):
                snap.append(("V", self.reg(s)))
        self.pending = (kind, dests, srcs, memi, snap,
                        (kind, INS[IDX[pc]].op_str, hex(pc)), lv)

    def body_words(self):
        by = {}
        for (sva, n, v) in self.ex.emit_trace:
            if (sva & 0xFFFFFFFFFFFF) == SINK:
                by[n & M32] = v & M32
        return [by.get(i) for i in range(48)]


def collect(value, prov, leaves, maxnodes=400000):
    seen = set()
    leaveset = set()
    nodes = 0
    depth = 0
    frontier = deque([(value, 0)])
    while frontier:
        v, d = frontier.popleft()
        if v in seen:
            continue
        seen.add(v)
        nodes += 1
        depth = max(depth, d)
        if nodes > maxnodes:
            break
        if v in leaves:
            leaveset.add(leaves[v])
            continue
        ent = prov.get(v)
        if ent is None:
            continue
        for par in ent[1]:
            if par[0] == "L":
                leaveset.add((par[1], par[2]))
            else:
                frontier.append((par[1], d + 1))
    return nodes, leaveset, depth


VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]


def descs_of(r):
    out = []
    for bi in VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        out.append((len(data) // 4, 0, data))
    return out


if __name__ == "__main__":
    i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    rows = json.load(open("all_signings.json"))
    ph3 = json.load(open("pair_h3.json"))
    ex = FinEx(ph3[i]["second"], descs_of(rows[i]))
    lin = Lineage(ex)
    ex.__dict__["_step_hook"] = lin.hook
    st = ex.run(max_steps=60_000_000)
    print("status", st, "steps", ex.steps, "prov", len(lin.prov), "leaves", len(lin.leaves))
    bw = lin.body_words()
    import pickle
    pickle.dump({"prov": lin.prov, "leaves": lin.leaves, "body": bw,
                 "steps": ex.steps, "status": st},
                open("_lin_%d.pkl" % i, "wb"))
    print("leaves:", sorted(set(lin.leaves.values())))
    for j in range(4, 48):
        v = bw[j]
        n, ls, d = collect(v, lin.prov, lin.leaves)
        print("body[%2d] %08x  nodes=%-6d depth=%-4d leaves=%s" % (
            j, v, n, d, sorted(ls)[:10]))
