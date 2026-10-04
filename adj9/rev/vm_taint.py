"""vm_taint.py — provenance (taint) execution of the adj9 serializer VM.

Runs the SAME program `fin_vm2.FinEx` runs (the proven forward encoder,
48/48 on the 6-row corpus) but every value carries a provenance DAG node.
Nothing in fin_vm2.py / vm_final.py / mint_pipeline.py is modified: the real
FinEx executes (so every VALUE is by construction the true wire value) and a
step-hook side band mirrors each instruction's dataflow onto DAG nodes.

Design (v2 — the lesson of the failed v1):
  v1 re-implemented the interpreter and derived node AND value together; its
  self-healing + interned-constant reuse produced value-matched-but-wrong
  constant nodes exactly where the whitening chain was computed.  v2 takes
  values ONLY from the real execution and tracks STRUCTURE conservatively:

    node kinds (tuples, interned):
      ('k', v)                    constant (v = the true run value)
      ('s', name)                 taint seed = one descriptor word
      ('rnd', i, v)               the i-th Random3(second) draw (TYPE_3)
      ('op', pc, mnem, v, kids)   one executed op; v = true result value
      ('sel', flagnode, taken, v) csel/cset result

  * every register write, memory store/load, queue PUSH/POP/CAP, stream
    EMIT/LENQ, PUSHS/POPS, MKITER/ITERNEXT carries nodes.
  * data-dependent control flow needs no modelling: the real run takes the
    real branches; a node only over-approximates dependence (e.g. a shift
    amount that is tainted marks the result tainted) — never under.
  * constants collapse: an op all of whose kids are constants becomes one
    ('k', result) node (pruning reconstructs this losslessly).

Taint seeds: EVERY descriptor word —
    d0[0]=W0 d0[1]=X d0[2]=T0 d0[3]=T1   (recovery targets)
    d2[0]=S (enters the wire at word 8)  d4[4]=F4 (enters at word 4)
    d4[0..3,5..7], d0[4..35], d5..d10[j] as named leaves d0[k] / d10[j] / ...
Random3 draws are ('rnd', i, v) — known to the decoder via the header law.
"""
from __future__ import annotations

import json
import os
import re
import struct
import sys
import time

sys.setrecursionlimit(400000)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fin_vm2 import FinEx                                  # noqa: E402
from vm_final import INS, IDX, PM                          # noqa: E402

M64 = (1 << 64) - 1
M32 = 0xFFFFFFFF
NREG = re.compile(r"^[wx]\d+$")

OP_PUSH, OP_POP = 0x147630, 0x147734
OP_PUSH2, OP_POP2 = 0x146470, 0x146478
OP_EMIT, OP_LENQ, OP_OUTLEN = 0x146ed8, 0x147304, 0x1472e8
OP_PUSHS, OP_POPS = 0x147120, 0x147220
OP_MKITER, OP_ITERNEXT = 0x146558, 0x146650
OP_RAND = 0x148d10
OP_ISEMPTY = 0x146474
CAP_SWAPS = {0x147a20}
CAP_PUSHS = {0x14784c, 0x147a18}
BL_OPS = {OP_PUSH, OP_PUSH2, OP_POP, OP_POP2, OP_EMIT, OP_LENQ, OP_OUTLEN,
          OP_RAND, OP_PUSHS, OP_POPS, OP_MKITER, OP_ITERNEXT, OP_ISEMPTY,
          0x147a20, 0x14784c, 0x147a18}

_ALUCACHE = {}


def canon(r):
    return ("w" + r[1:]) if (r and NREG.match(r)) else None


def rval(ex, r):
    """64-bit value of a register name from the REAL execution."""
    if not r or not NREG.match(r):
        return 0
    n = r[1:]
    if r[0] == "x":
        return ex.R.get("x" + n, ex.R.get("w" + n, 0)) & M64
    return ex.R.get("w" + n, 0) & M32


def _shift_of(p):
    """'lsl #3' part -> (kind, amount) or None."""
    if len(p) < 2:
        return None
    s = p[0]
    mm = re.match(r"(lsl|lsr|asr|uxtw|sxtw)", s)
    if not mm:
        return None
    amt = int(p[1].lstrip("#"), 0) if len(p) > 1 and p[1].startswith("#") else 0
    return (mm.group(1), amt)


def parse_alu(pc, m, o):
    """-> (dest, kid_specs); kid_spec = ('r', reg) | ('i', val) | ('sh', reg,
    kind, amt).  Cached per pc."""
    e = _ALUCACHE.get(pc)
    if e is not None:
        return e
    p = [x.strip() for x in o.split(",")]
    dest = p[0] if NREG.match(p[0]) else None
    kids = []
    i = 1
    while i < len(p):
        tok = p[i]
        if NREG.match(tok):
            sh = _shift_of(p[i + 1:i + 3]) if i + 1 < len(p) else None
            if sh and i + 2 < len(p) and not NREG.match(p[i + 1]):
                kids.append(("sh", tok, sh[0], sh[1]))
                i += 2
            else:
                # register-shift form 'lsl x4' (variable) — treat as reg kid
                if i + 1 < len(p) and NREG.match(p[i + 1]) and \
                        re.match(r"(lsl|lsr|asr)$", p[i + 1]):
                    kids.append(("r", tok))
                    kids.append(("r", p[i + 1]))
                    i += 2
                    continue
                kids.append(("r", tok))
                i += 1
        elif tok.startswith("#"):
            try:
                kids.append(("i", int(tok.lstrip("#"), 0)))
            except ValueError:
                kids.append(("i", 0))
            i += 1
        else:
            i += 1
    _ALUCACHE[pc] = (dest, kids)
    return dest, kids


_INTERN = {}
NN = [0]
_SEEDY = {}


def _seedy(nd):
    """Does this node carry descriptor-seed provenance? (memoized, eager)"""
    if nd is None:
        return False
    v = _SEEDY.get(id(nd))
    if v is not None:
        return v
    if nd[0] == "s":
        v = True
    elif nd[0] in ("k", "rnd"):
        v = False
    elif nd[0] == "sel":
        v = _seedy(nd[1]) or _seedy(nd[2])
    else:
        v = False
        for c in nd[4]:
            if _seedy(c):
                v = True
                break
    _SEEDY[id(nd)] = v
    return v


def mk(*a):
    n = _INTERN.get(a)
    if n is None:
        n = a
        _INTERN[a] = a
        NN[0] += 1
    return n


def K(v):
    return mk("k", v & M64)


def OPsel(fn, taken, v):
    return mk("sel", fn, taken, v)


def OP(pc, m, v, *kids):
    """Canonical op node: ('op', pc, m, v, kids-tuple)."""
    return mk("op", pc, m, v & M64 if isinstance(v, int) else v,
              tuple(kids))


class NodeStream:
    """Parallel of FinStream: top/acc mirrored, offs -> node."""
    __slots__ = ("top", "offs", "acc")

    def __init__(self):
        self.top = [0]
        self.offs = {}
        self.acc = 0

    def emit(self, n, node):
        idx = (self.top[-1] + (n & M32)) & M32
        self.offs[idx] = node
        if idx >= self.acc:
            self.acc = (idx + 1) & M32
        return idx

    def lenq(self, n):
        idx = (self.top[-1] + (n & M32)) & M32
        return self.offs.get(idx)

    def pushs(self):
        self.top.append(self.acc)

    def pops(self):
        if self.top:
            self.acc = self.top[-1]
            self.top.pop()


class Taint:
    """Step-hook side band over a live FinEx."""

    def __init__(self, ex, seednames):
        self.ex = ex
        self.R = {}                  # canon reg -> node
        self.Fn = {}                 # flag -> node
        self.mem = {}                # addr -> node
        self.q = {}                  # qva -> [node, ...] (parallel to queues)
        self.s = {}                  # sva -> NodeStream
        self.cache = {}
        self.pending = None
        self.nseed = 0
        self.names = {}
        # seeds: descriptor data words (little-endian dwords in ex.mem)
        for (bi, j), nm in seednames.items():
            pos = None
            for i, b in enumerate([0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]):
                if b == bi:
                    pos = i
                    break
            if pos is None:
                continue
            a = 0x5700000000 + pos * 0x1000 + 4 * j
            if a not in ex.mem:
                continue
            nd = mk("s", nm)
            self.mem[a] = nd
            self.names[nd] = nm
            self.nseed += 1
        self.tainted_csel = 0

    # -- helpers ---------------------------------------------------------
    def treg(self, r):
        c = canon(r)
        return self.R.get(c, K(0)) if c else K(0)

    def setr(self, r, node):
        c = canon(r)
        if c:
            self.R[c] = node
            _seedy(node)          # eager provenance flag (O(1) amortized)

    def tstream(self, va):
        s = self.s.get(va)
        if s is None:
            s = NodeStream()
            self.s[va] = s
        return s

    def addr(self, base, off, ex):
        bv = rval(ex, base)
        iv = rval(ex, off) if isinstance(off, str) else (off or 0)
        return (bv + iv) & M64

    def align(self, a, size):
        a &= PM
        return a & (~7 if size == 8 else ~3)

    def kid(self, spec, ex, pc):
        t = spec[0]
        if t == "r":
            return self.treg(spec[1])
        if t == "i":
            return K(spec[1])
        if t == "sh":
            base = self.treg(spec[1])
            kind, amt = spec[2], spec[3]
            if base[0] == "k":
                return K(self.kidval_sh(base[1], kind, amt))
            return OP(pc, kind, 0, base, K(amt))
        return K(0)

    @staticmethod
    def kidval_sh(v, kind, amt):
        if kind == "lsl":
            return (v << amt) & M64
        if kind in ("lsr", "asr"):
            return (v & M64) >> amt
        if kind in ("uxtw", "sxtw"):
            return ((v & M32) << amt) & M64
        return v

    def rnode(self, r, ex):
        """node + true value of a register (value from the real run)."""
        return self.treg(r), rval(ex, r)

    # -- the hook --------------------------------------------------------
    def hook(self, ex=None):
        ex = ex if ex is not None else self.ex
        if self.pending is not None:
            self._apply(self.pending)
        pc = ex.pc                    # pc of the instruction ABOUT to run
        info = self.cache.get(pc)
        if info is None:
            info = self._parse(pc)
            self.cache[pc] = info
        kind, extra = info
        R = ex.R
        if kind == "BL":
            t = extra
            if t in (OP_PUSH, OP_PUSH2):
                snap = (("qpush", rval(ex, "x1") & PM, self.treg("w2"),
                         R.get("w2", 0) & M32),)
            elif t in (OP_POP, OP_POP2):
                snap = (("qpop", rval(ex, "x1") & PM),)
            elif t == OP_EMIT:
                snap = (("emit", rval(ex, "x1") & PM, R.get("w2", 0) & M32,
                         self.treg("w3")),)
            elif t == OP_LENQ:
                snap = (("lenq", rval(ex, "x0") & PM, R.get("w1", 0) & M32),)
            elif t == OP_OUTLEN:
                snap = (("outlen", rval(ex, "x0") & PM),)
            elif t == OP_PUSHS:
                snap = (("pushs", rval(ex, "x1") & PM),)
            elif t == OP_POPS:
                snap = (("pops", rval(ex, "x1") & PM),)
            elif t in CAP_SWAPS:
                snap = (("capswap", rval(ex, "x1") & PM, R.get("w2", 0) & M32),)
            elif t in CAP_PUSHS:
                kk = 0 if t == 0x147a18 else (R.get("w2", 0) & M32)
                snap = (("cappush", rval(ex, "x1") & PM, kk),)
            elif t == OP_MKITER:
                snap = (("mkiter", rval(ex, "x1") & PM, self.treg("w2"),
                         R.get("w2", 0) & M32),)
            elif t == OP_ITERNEXT:
                snap = (("iternext", rval(ex, "x0") & PM),)
            elif t == OP_RAND:
                snap = (("rand", ex.nrand + 1),)
            elif t == OP_ISEMPTY:
                snap = (("isempty",),)
            else:
                snap = (("nop",),)
            self.pending = ("BL", snap, pc)
            return
        if kind == "mem":
            m, o = extra
            snap = self._mem_snap(m, o)
            self.pending = ("mem", snap, pc)
            return
        self.pending = (kind, extra, pc)

    def _mem_snap(self, m, o):
        ex = self.ex
        o2 = o.replace(" ", "")
        snap = {"m": m}
        if m in ("ldp", "stp", "ldpsw"):
            mm = re.match(r"^([wx]\d+),([wx]\d+),\[([^\]]+)\](.*)$", o2)
            d1, d2, inner, tail = mm.groups()
            parts = inner.split(",")
            base = parts[0]
            off = 0
            if len(parts) > 1:
                off = int(parts[1].lstrip("#"), 0) if                     parts[1].startswith("#") else 0
            snap.update(kind="pair", d1=d1, d2=d2, base=base, off=off,
                        wb=bool(tail),
                        a=self.addr(base, off, ex), v1=rval(ex, d1),
                        v2=rval(ex, d2))
            return snap
        mm = re.match(r"^([wx]\d+),\[([^\]]+)\](!?)$", o2)
        d, inner, wb = mm.group(1), mm.group(2), mm.group(3)
        parts = inner.split(",")
        base = parts[0]
        off = 0
        regoff = None
        sh = 0
        if len(parts) > 1:
            p2 = parts[1]
            if p2.startswith("#"):
                off = int(p2[1:], 0)
            else:
                regoff = p2
                if len(parts) > 2:
                    mm2 = re.match(r"(?:uxtw|lsl)#(\d+)", parts[2])
                    sh = int(mm2.group(1)) if mm2 else 0
        isload = m.startswith("ld")
        size = 8 if (d.startswith("x") and m not in
                     ("ldrsw", "ldursw", "ldrsh", "ldrh", "ldurb",
                      "ldrb")) else 4
        if regoff:
            a = (rval(ex, base) + ((rval(ex, regoff) & M32) << sh)) & M64
        else:
            a = self.addr(base, off, ex)
        snap.update(kind="single", d=d, base=base, off=off, wb=bool(wb),
                    isload=isload, size=size, a=a)
        return snap

    def _parse(self, pc):
        i = INS[IDX[pc]]
        m, o = i.mnemonic, i.op_str
        if m == "bl":
            try:
                t = int(o.strip().lstrip("#"), 0)
            except Exception:
                t = None
            return ("BL", t if t in BL_OPS else None)
        if m in ("ldr", "ldur", "str", "stur", "ldrb", "strb", "ldrsh",
                 "ldrh", "ldrsb", "ldrsw", "ldursw", "ldp", "stp",
                 "ldpsw", "ldurb", "ldurh", "sturb"):
            return ("mem", (m, o))
        if m in ("cmp", "cmn", "tst", "ccmp"):
            return ("cmp", (m, o))
        if m in ("csel", "csinc", "csinv", "csneg"):
            return ("csel", (m, o))
        if m == "cset":
            return ("cset", o)
        if m == "movk":
            return ("movk", o)
        if m in ("adr", "adrp", "mrs", "movi", "movz", "movn", "mvn"):
            return ("alu", (m, o))
        # every other data op: b / b.cc / cbz / ret / nop / svc -> no reg write
        if m.startswith("b") or m in ("ret", "nop", "svc", "brk"):
            return ("none", None)
        return ("alu", (m, o))

    def _apply(self, pend):
        kind, extra, pc = pend
        ex = self.ex
        if kind == "BL":
            for op in extra:
                t = op[0]
                if t == "qpush":
                    self.q.setdefault(op[1], []).insert(0, op[2])
                elif t == "qpop":
                    qq = self.q.get(op[1])
                    nd = qq.pop(0) if qq else K(ex.R.get("w0", 0) & M32)
                    v = ex.R.get("w0", 0) & M32
                    self.setr("w0", nd if nd is not None else K(v))
                    self.setr("x0", self.R.get("w0", K(0)))
                elif t == "emit":
                    s = self.tstream(op[1])
                    s.emit(op[2], op[3])
                elif t == "lenq":
                    s = self.tstream(op[1])
                    nd = s.lenq(op[2])
                    v = ex.R.get("w0", 0) & M32
                    self.setr("w0", nd if nd is not None else K(v))
                    self.setr("x0", self.R.get("w0", K(0)))
                elif t == "outlen":
                    self.setr("w0", K(ex.R.get("w0", 0) & M32))
                    self.setr("x0", self.R.get("w0", K(0)))
                elif t == "pushs":
                    self.tstream(op[1]).pushs()
                elif t == "pops":
                    self.tstream(op[1]).pops()
                elif t == "capswap":
                    qq = self.q.setdefault(op[1], [])
                    k2 = op[2]
                    if len(qq) > k2:
                        qq[0], qq[k2] = qq[k2], qq[0]
                elif t == "cappush":
                    qq = self.q.setdefault(op[1], [])
                    k2 = op[2]
                    if len(qq) > k2:
                        qq.insert(0, qq[k2])
                elif t == "mkiter":
                    self.q.setdefault(-1, [])  # no-op keepalive
                elif t == "iternext":
                    v = ex.R.get("w0", 0) & M32
                    self.setr("w0", K(v))   # counts: length-derived, known
                    self.setr("x0", self.R.get("w0", K(0)))
                elif t == "rand":
                    v = ex.R.get("w0", 0) & M32
                    nd = mk("rnd", op[1], v)
                    self.setr("w0", nd)
                    self.setr("x0", nd)
                elif t == "isempty":
                    self.setr("w0", K(ex.R.get("w0", 0) & M32))
                    self.setr("x0", self.R.get("w0", K(0)))
            return
        if kind == "none":
            return
        if kind == "mem":
            self._mem_apply2(extra, pc)
            return
        if kind == "cmp":
            m, o = extra
            p = [x.strip() for x in o.split(",")]
            srcs = [x for x in p if NREG.match(x)]
            kids = [self.treg(s) for s in srcs]
            vals = [rval(ex, s) for s in srcs]
            if all(k[0] in ("k", "rnd") for k in kids):
                fl = K(0)
            else:
                fl = mk("op", pc, m, 0, tuple(kids))
            self.Fn.update({f: fl for f in
                            ("eq", "ne", "lt", "ge", "gt", "le", "hs", "lo",
                             "hi", "ls")})
            return
        if kind == "csel":
            m, o = extra
            p = [x.strip() for x in o.split(",")]
            d, r1, r2, cond = p[0], p[1], p[2], p[3]
            taken = r1 if ex.F.get(cond.lstrip("!") or cond, False) else r2
            fn = self.Fn.get(cond, K(0))
            tn = self.treg(taken)
            v = rval(ex, d)
            if fn[0] == "k" and tn[0] in ("k", "rnd"):
                self.setr(d, K(v))
            else:
                if fn[0] != "k":
                    self.tainted_csel += 1
                self.setr(d, OPsel(fn, tn, v))
            return
        if kind == "cset":
            o = extra
            d, cond = [x.strip() for x in o.split(",")]
            fn = self.Fn.get(cond, K(0))
            v = rval(ex, d)
            if fn[0] == "k":
                self.setr(d, K(v))
            else:
                self.setr(d, OPsel(fn, K(1), v))
            return
        if kind == "movk":
            o = extra
            p = [x.strip() for x in o.replace(" ", "").split(",")]
            d = p[0]
            imm = int(p[1].lstrip("#"), 0)
            sh = 0
            if len(p) > 2:
                mm = re.match(r"lsl#(\d+)", p[2])
                sh = int(mm.group(1)) if mm else 0
            n0 = self.treg(d)
            v = rval(ex, d)
            if n0[0] in ("k", "rnd"):
                self.setr(d, K(v))
            else:
                self.setr(d, OP(pc, "movk", v, n0, K(imm), K(sh)))
            return
        # generic ALU
        m, o = extra
        dest, specs = parse_alu(pc, m, o)
        if dest is None:
            return
        kids = [self.kid(sp, ex, pc) for sp in specs]
        v = rval(ex, dest)
        if all(k[0] in ("k", "rnd") for k in kids):
            self.setr(dest, K(v))
        else:
            self.setr(dest, mk("op", pc, m, v, tuple(kids)))

    def _mem_apply2(self, sn, pc):
        ex = self.ex
        m = sn["m"]
        if sn["kind"] == "pair":
            a = sn["a"] & PM
            if m == "stp":
                self.mem[self.align(a, 8)] = self.treg(sn["d1"])
                self.mem[self.align(a + 8, 8)] = self.treg(sn["d2"])
            else:
                n1 = self.mem.get(self.align(a, 8))
                n2 = self.mem.get(self.align(a + 8, 8))
                self.setr(sn["d1"], n1 if n1 is not None else K(sn["v1"]))
                self.setr(sn["d2"], n2 if n2 is not None else K(sn["v2"]))
            if sn["wb"]:
                self.setr(sn["base"],
                          OP(pc, "add", rval(ex, sn["base"]),
   self.treg(sn["base"]), K(sn["off"])))
            return
        d, a, size = sn["d"], sn["a"], sn["size"]
        if not sn["isload"]:
            self.mem[self.align(a, size)] = self.treg(d)
        else:
            nd = self.mem.get(self.align(a, size))
            v = rval(ex, d)
            if nd is None:
                self.setr(d, K(v))
            elif m in ("ldrh", "ldurh"):
                self.setr(d, nd if (nd[0] in ("k", "rnd", "s") or
                                    (nd[0] == "op" and nd[2] == "w16"))
                          else OP(pc, "w16", v, nd))
            elif m in ("ldrsw", "ldursw"):
                self.setr(d, nd if (nd[0] in ("k", "rnd", "s") or
                                    (nd[0] == "op" and nd[2] == "sxtw"))
                          else OP(pc, "sxtw", v, nd))
            else:
                self.setr(d, nd if (size == 8 or nd[0] in ("k", "rnd", "s") or
                                    (nd[0] == "op" and nd[2] == "w32"))
                          else OP(pc, "w32", v, nd))
        if sn["wb"]:
            self.setr(sn["base"], OP(pc, "add", rval(ex, sn["base"]),
   self.treg(sn["base"]), K(sn["off"])))

    def _mem_apply(self, m, o, pc):
        ex = self.ex
        o2 = o.replace(" ", "")
        # ldp/stp
        if m in ("ldp", "stp", "ldpsw"):
            mm = re.match(
                r"^([wx]\d+),([wx]\d+),\[([^\]]+)\](.*)$", o2)
            if not mm:
                return
            d1, d2, inner, tail = mm.groups()
            parts = inner.split(",")
            base = parts[0]
            off = 0
            if len(parts) > 1:
                off = int(parts[1].lstrip("#"), 0) if \
                    parts[1].startswith("#") else 0
            wb = tail.startswith("!") or bool(tail)
            a = self.addr(base, off, ex)
            if m == "stp":
                self.mem[self.align(a, 8)] = self.treg(d1)
                self.mem[self.align(a + 8, 8)] = self.treg(d2)
            else:
                v1 = ex.R.get(d1[0] + d1[1:], 0)
                n1 = self.mem.get(self.align(a, 8))
                n2 = self.mem.get(self.align(a + 8, 8))
                self.setr(d1, n1 if n1 is not None else
                          K(rval(ex, d1)))
                self.setr(d2, n2 if n2 is not None else
                          K(rval(ex, d2)))
            if wb:
                self.setr(base, OP(pc, "add", rval(ex, base),
                                   self.treg(base), K(off)))
            return
        mm = re.match(r"^([wx]\d+),\[([^\]]+)\](!?)$", o2)
        if not mm:
            return
        d, inner, wb = mm.group(1), mm.group(2), mm.group(3)
        parts = inner.split(",")
        base = parts[0]
        off = 0
        regoff = None
        sh = 0
        if len(parts) > 1:
            p2 = parts[1]
            if p2.startswith("#"):
                off = int(p2[1:], 0)
            else:
                regoff = p2
                if len(parts) > 2:
                    mm2 = re.match(r"(?:uxtw|lsl)#(\d+)", parts[2])
                    sh = int(mm2.group(1)) if mm2 else 0
        isload = m.startswith("ld")
        size = 8 if (d.startswith("x") and m not in
                     ("ldrsw", "ldursw", "ldrsh", "ldrsh", "ldrh", "ldurb",
                      "ldrb")) else 4
        a = self.addr(base, regoff, ex) if regoff else self.addr(base, off, ex)
        if regoff:
            a = (rval(ex, base) + ((rval(ex, regoff) & M32) << sh)) & M64
        if not isload:
            self.mem[self.align(a, size)] = self.treg(d)
        else:
            nd = self.mem.get(self.align(a, size))
            v = rval(ex, d)
            if nd is None:
                self.setr(d, K(v))
            elif m in ("ldrh", "ldurh"):
                self.setr(d, nd if nd[0] in ("k", "rnd", "s")
                          or nd[1] == "w16" else OP(pc, "w16", v, nd))
            elif m in ("ldrsw", "ldursw"):
                self.setr(d, nd if nd[0] in ("k", "rnd", "s")
                          or nd[3] == "sxtw" else
                          OP(pc, "sxtw", v, nd))
            else:
                self.setr(d, nd if (size == 8 or nd[0] in ("k", "rnd", "s")
                                    or nd[1] == "w32")
                          else OP(pc, "w32", v, nd))
        if wb:
            self.setr(base, mk("op", pc, "add", rval(ex, base),
                               self.treg(base), K(off)))


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
SINK = 0x5500000000
BLOB_WORDS = 48

RECOVER = [(0, 0, "W0"), (0, 1, "X"), (0, 2, "T0"), (0, 3, "T1"),
           (2, 0, "S"), (4, 4, "F4")]


def default_seednames():
    out = {}
    for bi, j, nm in RECOVER:
        out[(bi, j)] = nm
    for bi, n in ((0, 36), (2, 1), (4, 8), (5, 1), (6, 1), (7, 1),
                  (8, 4), (9, 5)):
        for j in range(n):
            out.setdefault((bi, j), "%s[%d]" % (
                {0: "d0", 2: "d2", 4: "d4", 5: "d5", 6: "d6", 7: "d7",
                 8: "d8", 9: "d9"}[bi], j))
    return out


def corpus_row_descs(row):
    asg = json.load(open(os.path.join(HERE, "all_signings.json"),
                         encoding="utf-8"))
    r = asg[row]
    out = []
    for bi in VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        out.append((len(data) // 4, 0, data))
    return out


def corpus_row(row):
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json"),
                         encoding="utf-8"))
    p = ph3[row]
    return int(p["second"]), bytes.fromhex(p["blob"])


def run_taint(second, descs, seednames=None, max_steps=60_000_000):
    """Run the real FinEx with the node side band.  Returns (ex, tn, status)."""
    ex = FinEx(int(second), descs)
    tn = Taint(ex, seednames if seednames is not None else default_seednames())
    ex.__dict__["_step_hook"] = tn.hook
    st = ex.run(max_steps=max_steps)
    if tn.pending is not None:               # flush the last instruction
        tn._apply(tn.pending)
        tn.pending = None
    return ex, tn, st


def blob_words(ex, second=0, tn=None):
    """The 48 (value, node) pairs of the blob, exactly like finex_mint."""
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & M64, n & M32)] = v & M32
    bys = {}
    for (sva, n), v in last.items():
        bys.setdefault(sva, {})[n] = v
    from header_gen import make_header
    hdr = struct.unpack(">4I", make_header(int(second)))
    stream = None
    for sva in sorted(bys):
        if tuple(bys[sva].get(k, 0) for k in range(4)) == hdr:
            stream = sva
            break
    if stream is None:
        return None, None
    words = [(bys[stream].get(k, 0), tn_word(tn, stream, k) if tn else None)
             for k in range(BLOB_WORDS)]
    return words, stream


def tn_word(tn, stream, k):
    s = tn.s.get(stream)
    if s is None:
        return None
    return s.offs.get(k)


# ---------------------------------------------------------------------------
# DAG analysis
# ---------------------------------------------------------------------------
def _walk(nd, f, memo=None):
    """Post-order over the DAG; f(n, kids, memo) must write memo[id(n)]."""
    if memo is None:
        memo = {}
    stack = [(nd, False)]
    while stack:
        n, done = stack.pop()
        if id(n) in memo:
            continue
        kids = _kids(n)
        if not done:
            miss = [c for c in kids if id(c) not in memo]
            if miss:
                stack.append((n, True))
                for c in miss:
                    stack.append((c, False))
                continue
        f(n, kids, memo)
    return memo


def _kids(n):
    if n[0] == "op":
        return [c for c in n[4]] if isinstance(n[4], (list, tuple)) else []
    if n[0] == "sel":
        return [n[1], n[2]]
    return []


_SEEDMEMO = {}


def _f_seeded(n, kids, memo):
    memo[id(n)] = (n[0] == "s" or any(memo[id(c)] for c in kids))


def has_seed(nd, _m=None):
    return _seedy(nd)


def seed_set(nd, _m=None):
    if _m is None:
        def f(n, k, m):
            if n[0] == "s":
                m[id(n)] = {n[1]}
            else:
                s = set()
                for c in k:
                    s |= m[id(c)]
                m[id(n)] = s
        _m = _walk(nd, f)
    return _m.get(id(nd), set())


def depth(nd, _m=None):
    if _m is None:
        def f(n, k, m):
            m[id(n)] = 0 if n[0] in ("k", "s", "rnd") else \
                1 + max([m[id(c)] for c in k] or [0])
        _m = _walk(nd, f)
    return _m.get(id(nd), 0)


def nnodes(nd, _m=None):
    if _m is None:
        def f(n, k, m):
            m[id(n)] = 1 + sum(m[id(c)] for c in k)
        _m = _walk(nd, f)
    return _m.get(id(nd), 0)


def op_hist(nd, _m=None):
    if _m is None:
        def f(n, k, m):
            h = {}
            for c in k:
                for kk, vv in m[id(c)].items():
                    h[kk] = h.get(kk, 0) + vv
            if n[0] == "op":
                h[n[2]] = h.get(n[2], 0) + 1
            m[id(n)] = h
        _m = _walk(nd, f)
    return _m.get(id(nd), {})


def fmt(nd, seen=None):
    """Compact expression; subtrees with no seed collapse to their value."""
    if seen is None:
        seen = set()
    if id(nd) in seen:
        return "<cyc>"
    seen = seen | {id(nd)}
    t = nd[0]
    if t == "k":
        return "0x%x" % (nd[1] & M64)
    if t == "s":
        return nd[1]
    if t == "rnd":
        return "rnd%d" % nd[1]
    if t == "sel":
        if not has_seed(nd[1]):
            return fmt(nd[2], seen)
        return "sel(%s ? %s)" % (fmt(nd[1], seen), fmt(nd[2], seen))
    m = nd[2]
    kids = nd[4]
    if not has_seed(nd):
        return "0x%x" % (nd[3] & M64)
    if all((not has_seed(c)) for c in kids):
        return "%s(%s)" % (m, ",".join("0x%x" % (c[1] & M64)
                                       if c[0] == "k" else fmt(c, seen)
                                       for c in kids))
    return "%s(%s)" % (m, ",".join(fmt(c, seen) for c in kids))


def prune(nd, memo=None):
    """Copy the DAG replacing every constant subtree by ('k', value)."""
    if memo is None:
        memo = {}
    if id(nd) in memo:
        return memo[id(nd)]
    if nd[0] in ("k", "s", "rnd"):
        return nd
    if nd[0] == "sel":
        if not has_seed(nd[1]):
            out = prune(nd[2], memo)
        else:
            out = ("sel", prune(nd[1], memo), prune(nd[2], memo), nd[3])
        memo[id(nd)] = out
        return out
    kids = [prune(c, memo) for c in nd[4]]
    if not any(has_seed(c) for c in kids):
        out = K(nd[3])
    else:
        out = (nd[0], nd[1], nd[2], nd[3], tuple(kids))
    memo[id(nd)] = out
    return out


# ---------------------------------------------------------------------------
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--row", type=int, default=7)
    ap.add_argument("--dump", default="")
    ap.add_argument("--maxsteps", type=int, default=60_000_000)
    a = ap.parse_args()
    descs = corpus_row_descs(a.row)
    second, cap = corpus_row(a.row)
    t0 = time.time()
    ex, tn, st = run_taint(second, descs, default_seednames(),
                           max_steps=a.maxsteps)
    words, stream = blob_words(ex, second, tn)
    ok = words is not None and b"".join(struct.pack(">I", w[0] & M32)
                                        for w in words) == cap
    print("status=%s steps=%d nrand=%d nodes=%d  %.0fs"
          % (st, ex.steps, ex.nrand, NN[0], time.time() - t0), flush=True)
    print("stream=0x%x blob_match=%s tainted_csel=%d seeds=%d"
          % (stream or 0, ok, tn.tainted_csel, tn.nseed), flush=True)
    report = {"row": a.row, "second": second, "blob": cap.hex(),
              "blob_match": ok, "words": {}}
    if words:
        for i, (v, nd) in enumerate(words):
            if nd is None:
                print("w%-2d <none>" % i, flush=True)
                continue
            ss = sorted(seed_set(nd))
            hh = op_hist(nd)
            print("w%-2d seeds=%-30s depth=%-3d nodes=%-5d ops=%s %s"
                  % (i, ",".join(ss)[:30], depth(nd), nnodes(nd),
                     ("%s" % dict(hh) if hh else "{}"), fmt(nd)[:900]),
                  flush=True)
            report["words"][str(i)] = {
                "value": "%08x" % (v & M32), "seeds": ss,
                "depth": depth(nd), "nnodes": nnodes(nd),
                "ops": {k: vv for k, vv in hh.items()},
                "expr": fmt(nd)[:20000], "dag": prune(nd)}
    if a.dump:
        json.dump(report, open(a.dump, "w"))
        print("dumped %s (%.1f MB)"
              % (a.dump, os.path.getsize(a.dump) / 1e6), flush=True)


if __name__ == "__main__":
    main()
