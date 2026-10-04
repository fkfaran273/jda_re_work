"""_taint.py - symbolic taint tracking over fin_vm2.FinEx.

The value-keyed lineage in _lineage.py collapses because 10.5M steps reuse
only ~53k distinct 32-bit values.  Taint labels are immune to that: every
descriptor-plane word gets its own bit, and every register / memory cell /
queue node / stream slot carries a Python-int bitmask of the words it depends
on.  The hook is driven by the same instruction parser as _lineage.py but only
uses OPERAND SETS (no value semantics), so it is conservative-correct.

Outputs, for each of the 48 body words, the exact set of descriptor-plane
words it depends on: the dependency matrix that decides whether the body is
word-separable (invertible per block) or a full avalanche mix.
"""
import json
import re
import struct
import sys
from collections import deque

sys.path.insert(0, ".")
from fin_vm2 import FinEx
from vm_final import INS, IDX

M32 = 0xFFFFFFFF
PM = 0x0000FFFFFFFFFFFF
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


def canon(r):
    """w5 / x5 / w5 -> 'w5' so x/w aliasing shares one taint slot."""
    return "w" + r[1:] if NREG.match(r) else None


def _memop(o, m):
    o = o.replace(" ", "")
    mm2 = re.match(r"^([A-Za-z0-9_.]+),\[([A-Za-z0-9]+)\],#(-?[\dxa-f]+)$", o)
    if mm2:
        d, base, imm = mm2.group(1), mm2.group(2), int(mm2.group(3), 0)
        return [d], [], ("mem", base, imm, d, "post")
    mm = re.match(r"^([A-Za-z0-9_.]+),\[([^\]]+)\](!?)$", o)
    if not mm:
        return None
    d, inner = mm.group(1), mm.group(2)
    parts = inner.split(",")
    base = parts[0]
    off = 0
    if len(parts) >= 2:
        p2 = parts[1]
        off = int(p2[1:], 0) if p2.startswith("#") else p2
    kind = "store" if m.startswith("st") else "load"
    if not NREG.match(d):
        return [], [], ("mem", base, off, None, kind)
    if kind == "store":
        return [], [d], ("mem", base, off, d, kind)
    return [d], [], ("mem", base, off, d, kind)


def parse(pc):
    i = INS[IDX[pc]]
    m, o = i.mnemonic, i.op_str
    if m == "bl":
        t = None
        try:
            t = int(o.strip().lstrip("#"), 0)
        except Exception:
            t = None
        if t in BL_HELPERS:
            return ("BL", t, [], [], None)
        return ("BLX", t, [], [], None)
    if m == "blr":
        return ("BLRX", None, [], [], None)
    if m in ("b", "br", "ret", "nop"):
        return (m, None, [], [], None)
    if m in ("cbz", "cbnz", "tbz", "tbnz"):
        return (m, None, [], [], None)
    if m in ("ldr", "ldur", "str", "stur", "ldrb", "strb", "ldrsh", "ldrh",
             "ldrsb", "ldrsw", "ldursw", "ldp", "stp", "ldpsw"):
        if m in ("ldp", "stp", "ldpsw"):
            o2 = o.replace(" ", "")
            mm = re.match(r"^([A-Za-z0-9_.]+),([A-Za-z0-9_.]+),\[([^\]]+)\]([a-z0-9]+)?$", o2)
            if not mm:
                return (m, None, [], [], None)
            d1, d2, inner, idx = mm.group(1), mm.group(2), mm.group(3), mm.group(4) or ""
            parts = inner.split(",")
            base = parts[0]
            off = int(parts[1][1:], 0) if len(parts) > 1 and parts[1].startswith("#") else 0
            imm = -int(idx[1:]) if idx.startswith("#-") else (int(idx[1:], 0) if idx else 0)
            kind = "store" if m == "stp" else "load"
            dests = [] if kind == "store" else [d1, d2]
            srcs = [d1, d2] if kind == "store" else []
            return (m, (d1, d2, base, off, imm, kind), dests, srcs, None)
        r = _memop(o, m)
        if r is None:
            return (m, None, [], [], None)
        dests, srcs, memi = r
        return (m, memi, dests, srcs, None)
    if m in ("cmp", "cmn", "tst", "ccmp", "ccmn"):
        p = [x.strip() for x in o.split(",")]
        return (m, None, [], [x for x in p if NREG.match(x)], None)
    if m in ("csel", "cset", "csetm"):
        p = [x.strip() for x in o.split(",")]
        d = p[0]
        srcs = [x for x in p[1:] if NREG.match(x)]
        return (m, None, [d], srcs, None)
    p = [x.strip() for x in o.split(",")]
    d = p[0] if p else ""
    dests = [d] if NREG.match(d) else []
    srcs = [x for x in p[1:] if NREG.match(x)]
    return (m, None, dests, srcs, None)


class TStream:
    __slots__ = ("top", "offs", "acc")

    def __init__(self):
        self.top = [0]
        self.offs = {}
        self.acc = 0

    def emit(self, n, mask):
        idx = (self.top[-1] + (n & M32)) & M32
        self.offs[idx] = mask
        if idx >= self.acc:
            self.acc = idx + 1
        return idx

    def lenq(self, n):
        idx = (self.top[-1] + (n & M32)) & M32
        return self.offs.get(idx, 0)

    def pushs(self):
        self.top.append(self.acc)

    def pops(self):
        if not self.top:
            return 7
        self.acc = self.top[-1]
        self.top.pop()
        return 0


class Taint:
    def __init__(self, ex, descs):
        self.ex = ex
        self.R = {}                      # canon reg -> mask
        self.mem = {}                    # addr -> mask
        self.q = {}                      # qva -> [mask, ...]  (head at 0)
        self.s = {}                      # sva -> TStream
        self.cache = {}
        self.pending = None
        # leaf bits: (desc_pos, word_idx) -> bit
        self.leaf = {}
        b = 0
        for di, (lendl, tag, data) in enumerate(descs):
            for j in range(lendl):
                self.leaf[(di, j)] = b
                b += 1
        self.nbits = b
        for (di, j), bit in self.leaf.items():
            self.mem[DESC_BASE + di * DESC_STRIDE + 4 * j] = 1 << bit
        self.unknown_bl = set()

    def treg(self, r):
        c = canon(r)
        return self.R.get(c, 0) if c else 0

    def setr(self, r, mask):
        c = canon(r)
        if c:
            self.R[c] = mask

    def tstream(self, va):
        s = self.s.get(va)
        if s is None:
            s = TStream()
            self.s[va] = s
        return s

    # ---- address computation ----
    def rval(self, r):
        """64-bit value of a register name, honouring x/w aliasing."""
        R = self.ex.R
        if not r or not NREG.match(r):
            return 0
        n = r[1:]
        if r[0] == "x":
            return R.get("x" + n, R.get("w" + n, 0)) & 0xFFFFFFFFFFFFFFFF
        return R.get("w" + n, 0) & 0xFFFFFFFF

    def addr(self, base, off):
        bv = self.rval(base)
        iv = self.rval(off) if isinstance(off, str) else off
        return (bv + iv) & 0xFFFFFFFFFFFFFFFF

    def hook(self, ex=None):
        ex = ex if ex is not None else self.ex
        p = self.pending
        if p is not None:
            self._apply(p)
        pc = ex.pc
        info = self.cache.get(pc)
        if info is None:
            info = parse(pc)
            self.cache[pc] = info
        kind, extra, dests, srcs, _ = info
        R = ex.R
        if kind == "BL":
            t = extra
            if t in (OP_PUSH, OP_PUSH2):
                snap = (("qpush", (self.rval("x1") & PM), self.treg("w2")),)
            elif t in (OP_POP, OP_POP2):
                snap = (("qpop", self.rval("x1") & PM),)
            elif t == OP_EMIT:
                snap = (("emit", self.rval("x1") & PM, R.get("w2", 0), self.treg("w3")),)
            elif t == OP_LENQ:
                snap = (("lenq", self.rval("x0") & PM, R.get("w1", 0)),)
            elif t == 0x147120:
                snap = (("pushs", self.rval("x1") & PM),)
            elif t == 0x147220:
                snap = (("pops", self.rval("x1") & PM),)
            elif t == 0x147a20:
                snap = (("capswap", self.rval("x1") & PM, R.get("w2", 0) & M32),)
            elif t in (0x14784c, 0x147a18):
                kk = 0 if t == 0x147a18 else (R.get("w2", 0) & M32)
                snap = (("cappush", self.rval("x1") & PM, kk),)
            elif t == OP_RAND:
                snap = (("rand",),)
            elif t == OP_OUTLEN:
                snap = (("outlen", self.rval("x0") & PM),)
            elif t == 0x146474:
                snap = (("isempty", (self.rval("x0") or self.rval("x1")) & PM),)
            else:
                snap = (("nop",),)
            self.pending = ("BL", t, dests, srcs, snap)
            return
        if kind == "BLX":
            self.unknown_bl.add(hex(extra))
            self.pending = (kind, extra, dests, srcs, (("clr", "w0"),))
            return
        if kind == "BLRX":
            self.pending = (kind, extra, dests, srcs, (("clr", "x0"),))
            return
        if extra is None:
            mask = 0
            for s in srcs:
                mask |= self.treg(s)
            if kind in ("cbz", "cbnz", "tbz", "tbnz") and srcs:
                mask |= self.treg(srcs[0])
            self.pending = (kind, extra, dests, srcs, (("set", tuple(dests), mask),))
            return
        if extra[0] == "mem":
            _, base, off, sreg, mk = extra
            a = self.addr(base, off)
            if mk == "store":
                snap = (("store", a, self.treg(sreg)),)
            else:
                snap = (("load", a, canon(sreg)),)
            self.pending = (kind, extra, dests, srcs, snap)
            return
        # ldp / stp
        d1, d2, base, off, imm, mk = extra
        a = self.addr(base, off)
        if mk == "store":
            snap = (("store2", a, canon(d1), canon(d2)),)
        else:
            snap = (("load2", a, canon(d1), canon(d2)),)
        self.pending = (kind, extra, dests, srcs, snap)

    def _apply(self, p):
        kind, extra, dests, srcs, snap = p
        for op in snap:
            t = op[0]
            if t == "set":
                for d in op[1]:
                    self.setr(d, op[2])
            elif t == "clr":
                self.setr(op[1], 0)
            elif t == "store":
                self.mem[op[1]] = op[2]
            elif t == "load":
                self.setr(op[2], self.mem.get(op[1], 0))
            elif t == "store2":
                self.mem[op[1]] = self.R.get(op[2], 0)
                self.mem[(op[1] + 8) & 0xFFFFFFFF] = self.R.get(op[3], 0)
            elif t == "load2":
                v1 = self.mem.get(op[1], 0)
                v2 = self.mem.get((op[1] + 8) & 0xFFFFFFFF, 0)
                self.setr(op[2], v1)
                self.setr(op[3], v2)
            elif t == "qpush":
                self.q.setdefault(op[1], []).insert(0, op[2])
            elif t == "qpop":
                qq = self.q.get(op[1])
                self.setr("w0", qq.pop(0) if qq else 0)
            elif t == "emit":
                s = self.tstream(op[1])
                s.emit(op[2], op[3])
            elif t == "lenq":
                s = self.tstream(op[1])
                self.setr("w0", s.lenq(op[2]))
            elif t == "pushs":
                self.tstream(op[1]).pushs()
            elif t == "pops":
                self.tstream(op[1]).pops()
            elif t == "capswap":
                qq = self.q.setdefault(op[1], [])
                k = op[2]
                if len(qq) > k:
                    qq[0], qq[k] = qq[k], qq[0]
            elif t == "cappush":
                qq = self.q.setdefault(op[1], [])
                k = op[2]
                if len(qq) > k:
                    qq.insert(0, qq[k])
            elif t == "rand":
                self.setr("w0", 0)
            elif t == "outlen":
                self.setr("w0", 0)
            elif t == "isempty":
                self.setr("w0", 0)

    def sink_mask(self, n):
        s = self.s.get(SINK)
        if s is None:
            return 0
        return s.offs.get(n, 0)


VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]


def descs_of(r):
    out = []
    for bi in VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        out.append((len(data) // 4, 0, data))
    return out


def bitname(bit):
    for (di, j), b in LEAFBIT.items():
        if b == bit:
            return "d%d[%d]" % (VA_ORDER[di], j)
    return "?%d" % bit


LEAFBIT = {}


if __name__ == "__main__":
    i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    rows = json.load(open("all_signings.json"))
    ph3 = json.load(open("pair_h3.json"))
    d = descs_of(rows[i])
    ex = FinEx(ph3[i]["second"], d)
    nd = []
    for lendl, tag, data in d:
        raw = bytes(data)
        padded = raw + b"\x00" * (-len(raw) % 4)
        nd.append((max(int(lendl), len(padded) // 4), tag, padded))
    t = Taint(ex, nd)
    LEAFBIT.update(t.leaf)
    ex.__dict__["_step_hook"] = t.hook
    st = ex.run(max_steps=60_000_000)
    print("status", st, "steps", ex.steps, "nbits", t.nbits,
          "unk_bl", sorted(t.unknown_bl))
    names = [bitname(b) for b in range(t.nbits)]
    for n in range(48):
        mk = t.sink_mask(n)
        lbl = [names[i] for i in range(t.nbits) if (mk >> i) & 1]
        print("w%-2d  nbits=%-4d %s" % (n, bin(mk).count("1"), " ".join(lbl)))
