"""fin_vm2_fast.py — the adj9 FinEx VM, same output, ~10x less Python work.

`FinEx` here subclasses the reference `fin_vm2.FinEx` (identical setup: the
descriptor plane, FinStream model, Random3) and replaces only `run()`.  The
interpreter loop is the block-compiled one from gen.py: ~10k straight-line
Python functions generated from the decoded ARM64, dispatched by pc.

Correctness contract: every emitted instruction is a transcription of
fin_vm2.FinEx.run (including the vm_final.Ex helpers it calls), so the mint is
byte-identical.  Any operand form the emitter does not model routes through
GEN(), which re-implements the original per-mnemonic branch verbatim.

    python fin_vm2_fast.py            # compile blocks + report timings
"""
import os
import sys
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
for _p in (HERE, REV):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import vmgen as G                                              # noqa: E402
from vmgen import (M32, M64, PM, VMExit, FREES, _GPR, pt,    # noqa: E402
                 COND, CIDX, _memplan)

import fin_vm2 as REF                                         # noqa: E402
import vm_final as V                                         # noqa: E402

FinStream = REF.FinStream


class MemDict(dict):
    """mem with a missing-key default of 0, so a generated load is a plain
    subscript (BINARY_SUBSCR) instead of a .get() method call."""

    def __missing__(self, key):
        return 0
PCADDR = None
BL = None
CODES = None
_NGEN = 0


def prepare(verbose=False, force=False):
    """Decode (or load the frozen decode), split into blocks, compile."""
    global PCADDR, BL, CODES, _NGEN
    t, sig = G.load_tables()
    fast = t["FAST"]
    pcaddr = t["PC"]
    cache = os.path.join(HERE, "vm_blocks_%s-%s.marshal" % (sig, G.VERSION))
    if force and os.path.exists(cache):
        os.remove(cache)
    t0 = time.time()
    bl, codes, ngen, cached = G.compile_blocks(fast, pcaddr, sig, verbose=verbose)
    dt = time.time() - t0
    PCADDR, BL, CODES, _NGEN = pcaddr, bl, codes, ngen
    if verbose:
        print("blocks=%d  fast=%d  generic=%d  %s  %.2fs"
              % (len(bl), ngen, len(bl) - ngen,
                 "cached" if cached else "compiled", dt))
    return dt


_GENV = {"M64": M64, "M32": M32, "M16": 0xFFFF, "PM": PM,
         "MASK8": G.MASK8, "MASK4": G.MASK4, "pt": pt, "CIDX": CIDX,
         "COND": COND, "G": G, "os": os, "sys": sys, "types": types,
         "_rev": G._rev}
_gen_block_template = """
def _blk():
%s
"""


class FinEx(REF.FinEx):
    """Reference FinEx with the block-compiled interpreter."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        # a plain dict cannot be re-classed, so swap in the __missing__=0
        # variant once the descriptor plane is in place (nothing else keeps a
        # reference to the old dict: FinEx.__init__ already replaced every
        # StreamObj with a FinStream)
        self.mem = MemDict(self.mem)

    # ------------------------------------------------------------------
    def run(self, max_steps=4_000_000):
        global _NGEN
        if BL is None:
            prepare()

        R = self.R
        mem = self.mem
        # ---- register file: X[0..30] = x0..x30, X[31] = sp -------------
        X = [0] * 32
        for k, v in R.items():
            if k == "sp":
                X[31] = v
                continue
            c = k[0]
            if c in "wx" and k[1:].isdigit():
                n = int(k[1:])
                if n <= 30:
                    X[n] = v & M32 if c == "w" else v
        FL = [False] * 10
        VD = R                     # vector/other regs: reference dict, live
        EMIT = self.emit_trace
        Q = self.queues
        IT = self.iters
        SR = self.streams
        RND = self.rnd
        NR = [0]
        SH = self.__dict__.setdefault("_shadow", [])
        self = self

        # ---- semantic ops (transcriptions of the bl handlers) ----------
        def PUSH():
            Q.setdefault(X[1], []).insert(0, X[2] & M32)

        def POP():
            q = Q.get(X[1])
            if q:
                X[0] = q.pop(0) & M32
            else:
                mem[X[19]] = 3
                X[0] = 0

        def EMIT_():
            va = X[1] & PM
            s = SR.get(va)
            if s is None:
                s = SR[va] = FinStream(va)
            n = X[2]
            v = X[3]
            s.emit(n, v)
            EMIT.append((s.va, n & M32, v & M32))

        def LENQ():
            va = X[0] & PM
            s = SR.get(va)
            if s is None:
                s = SR[va] = FinStream(va)
            X[0] = s.lenq(X[1]) & M32

        def OUTLEN():
            va = X[0] & PM
            s = SR.get(va)
            if s is None:
                s = SR[va] = FinStream(va)
            X[0] = s.outlen() & M32

        def PUSHS():
            va = X[1] & PM
            s = SR.get(va)
            if s is None:
                s = SR[va] = FinStream(va)
            s.pushs()

        def POPS():
            va = X[1] & PM
            s = SR.get(va)
            if s is None:
                s = SR[va] = FinStream(va)
            err = s.pops()
            if err:
                mem[X[19]] = err

        def CAP_SWAP():
            q = Q.setdefault(X[1], [])
            k = X[2] & M32
            if len(q) <= k:
                mem[X[19]] = 4
            else:
                q[0], q[k] = q[k], q[0]

        def CAP_PUSH0():
            q = Q.setdefault(X[1], [])
            if not q:
                mem[X[19]] = 4
            else:
                q.insert(0, q[0])

        def CAP_PUSH():
            q = Q.setdefault(X[1], [])
            k = X[2] & M32
            if len(q) <= k:
                mem[X[19]] = 4
            else:
                q.insert(0, q[k])

        def MKITER():
            cell = X[1] & PM
            n = self.__dict__.get("_nit", 0)
            nva = 0x5800000000 + n * 0x100
            self.__dict__["_nit"] = n + 1
            IT[nva] = {"count": X[2] & M32, "next": mem.get(cell)}
            mem[cell] = nva
            X[0] = nva

        def ITERNEXT():
            cell = X[0] & PM
            nva = mem.get(cell)
            node = IT.get(nva) if nva is not None else None
            if node is None:
                X[0] = 0
            else:
                c = (node["count"] - 1) & M32
                node["count"] = c
                if c == 0:
                    mem[cell] = node["next"]
                    IT.pop(nva, None)
                X[0] = c

        def ISEMPTY():
            qva = X[0] or X[1]
            X[0] = 1 if not Q.get(qva) else 0

        def RAND_():
            X[0] = RND.next() & M32
            NR[0] += 1

        def GEN(m, ops, npc):
            """Verbatim fallback for an instruction the emitter did not model."""
            return self._generic(m, ops, npc, X, FL, mem, Q, IT, SR, EMIT,
                                 RND, NR)

        ns = {"X": X, "MEM": mem, "FL": FL, "VD": VD, "EMIT": EMIT, "Q": Q,
              "IT": IT, "SR": SR, "RND": RND, "NR": NR, "SH": SH,
              "EXIT": VMExit, "PUSH": PUSH, "POP": POP, "EMIT_": EMIT_,
              "LENQ": LENQ, "OUTLEN": OUTLEN, "PUSHS": PUSHS, "POPS": POPS,
              "MKITER": MKITER, "ITERNEXT": ITERNEXT, "ISEMPTY": ISEMPTY,
              "RAND_": RAND_, "CAP_SWAP": CAP_SWAP, "CAP_PUSH0": CAP_PUSH0,
              "CAP_PUSH": CAP_PUSH, "GEN": GEN, "self": self,
              "T": self.__dict__.get("_T")}

        vals = [ns[nm] for nm in G.FREES]
        BPM = {}
        for (i0, _i1), code in zip(BL, CODES):
            fn = types.FunctionType(code, _GENV)
            BPM[PCADDR[i0]] = fn(*vals)

        pc = self.pc
        steps = 0
        status = "steps"
        try:
            while steps < max_steps:
                steps += 1
                pc = BPM[pc]()
        except VMExit as e:
            status = e.args[0]
        except KeyError as e:
            status = "pc-out"
            self.__dict__["_bad_pc"] = pc
            self.__dict__["_bpm_n"] = len(BPM)
            self.__dict__["_has_bad"] = pc in BPM

        # ---- write state back ----------------------------------------
        for n in range(31):
            v = X[n]
            R["x%d" % n] = v & M64
            R["w%d" % n] = v & M32
        R["sp"] = X[31] & M64
        F = self.F
        F.clear()
        for i, c in enumerate(COND):
            F[c] = FL[i]
        self.pc = pc
        self.steps = steps
        self.nrand = NR[0]
        return status

    # ------------------------------------------------------------------
    def _generic(self, m, ops, npc, X, FL, mem, Q, IT, SR, EMIT, RND, NR):
        """One instruction, exactly as fin_vm2.FinEx.run would do it.

        Only reached for operand forms the fast emitter rejects.
        """
        R = self.R
        F = self.F

        def rd(s):
            s = s.strip()
            if s in ("wzr", "xzr"):
                return 0
            if s == "sp":
                return X[31]
            if s[0] == "#":
                v = pt(s)
                return v or 0
            mm = _GPR.match(s)
            if mm and int(mm.group(2)) <= 30:
                n = int(mm.group(2))
                return (X[n] & M32) if mm.group(1) == "w" else X[n]
            if s in R:
                return R[s]
            try:
                return int(s, 0)
            except ValueError:
                return 0

        def wr(d, v):
            d = d.strip()
            if d in ("wzr", "xzr"):
                return
            if d == "sp":
                X[31] = v & M64
                return
            mm = _GPR.match(d)
            if mm and int(mm.group(2)) <= 30:
                n = int(mm.group(2))
                X[n] = (v & M32) if mm.group(1) == "w" else (v & M64)
                return
            R[d] = v & M64

        def fget(c):
            return F.get(c, False)

        p = [x.strip() for x in ops.split(",")] if ops else []

        if m == "bl":
            t = pt(ops)
            if t is None:
                self.__dict__.setdefault("_unk_bl", set()).add(hex(0))
                return npc
            # reuse the run()-installed ops by re-deriving them here
            return self._gen_bl(t, X, mem, Q, IT, SR, EMIT, RND, NR, npc)
        if m == "blr":
            wr("x0", 0)
            return npc
        if m == "mrs":
            R[ops.split(",")[0].strip()] = 0x1000
            return npc
        if m in ("mov", "movz"):
            wr(p[0], rd(p[1]))
            return npc
        if m == "movk":
            import re as _re
            mm = _re.match(r"^(\w+),#(0x[0-9a-f]+|\d+)(?:,lsl#(\d+))?",
                           ops.replace(" ", ""))
            if mm:
                d, imm, sh = mm.group(1), int(mm.group(2), 0), int(mm.group(3) or 0)
                wr(d, (rd(d) & ~(0xFFFF << sh)) | ((imm & 0xFFFF) << sh))
            return npc
        if m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr",
                 "rev", "rev16", "neg", "mvn", "udiv", "msub"):
            a = rd(p[1])
            b = rd(p[2]) if len(p) > 2 else 0
            if len(p) > 3:
                import re as _re
                mm2 = _re.match(r"(lsl|lsr|uxtw|sxtw)#(\d+)", p[3].replace(" ", ""))
                if mm2:
                    k = int(mm2.group(2))
                    if mm2.group(1) == "lsl":
                        b = (b << k) & M64
                    elif mm2.group(1) == "lsr":
                        b = (b >> k) & M64
                    elif mm2.group(1) in ("uxtw", "sxtw"):
                        b = ((b & M32) << k) & M64
            if m == "udiv":
                a &= M32
                b &= M32
                v = (a // b) if b else 0
                if p[0].startswith("w"):
                    v &= M32
                wr(p[0], v)
                return npc
            if m == "msub":
                v = (rd(p[3]) - a * b) & M64
                if p[0].startswith("w"):
                    v &= M32
                wr(p[0], v)
                return npc
            if m == "add":
                v = (a + b) & M64
            elif m == "sub":
                v = (a - b) & M64
            elif m == "eor":
                v = a ^ b
            elif m == "and":
                v = a & b
            elif m == "orr":
                v = a | b
            elif m == "mul":
                v = (a * b) & M64
            elif m == "lsl":
                v = (a << b) & M64
            elif m == "lsr":
                v = a >> b
            elif m == "rev":
                v = int.from_bytes((a & M32).to_bytes(4, "little"), "big")
            elif m == "rev16":
                v = ((a & 0xFFFF) << 16) | ((a >> 16) & 0xFFFF)
            elif m == "neg":
                v = (-a) & M64
            else:
                v = ~a & M64
            wr(p[0], v)
            return npc
        if m in ("cmp", "cmn", "tst"):
            a = rd(p[0])
            b = rd(p[1]) if len(p) > 1 else 0
            if p[0].lstrip().startswith("w"):
                a &= M32
                b &= M32
                if m == "cmn":
                    r = a + b
                    d = r & M32
                    C = r > M32
                    N = (d >> 31) & 1
                    Vv = ((~(a ^ b) & (a ^ d)) >> 31) & 1
                elif m == "cmp":
                    r = a - b
                    d = r & M32
                    C = a >= b
                    N = (d >> 31) & 1
                    Vv = (((a ^ b) & (a ^ d)) >> 31) & 1
                else:
                    d = a & b
                    C = False
                    N = (d >> 31) & 1
                    Vv = False
                FL[0] = d == 0
                FL[1] = d != 0
                FL[2] = N != Vv
                FL[3] = N == Vv
                FL[4] = (d != 0) and (N == Vv)
                FL[5] = (d == 0) or (N != Vv)
                FL[6] = C
                FL[7] = not C
                FL[8] = C and (d != 0)
                FL[9] = (not C) or (d == 0)
                return npc
            if m == "cmn":
                d = (a + b) & M64
                sg = a + b
            elif m == "tst":
                d = a & b
                sg = d
            else:
                d = (a - b) & M64
                sg = a - b
            FL[0] = d == 0
            FL[1] = d != 0
            FL[2] = sg < 0
            FL[3] = sg >= 0
            FL[4] = sg > 0
            FL[5] = sg <= 0
            FL[8] = d > 0
            FL[9] = d <= 0
            if m == "cmp":
                FL[6] = a >= b
                FL[7] = a < b
            elif m == "cmn":
                FL[6] = True
                FL[7] = False
            else:
                FL[6] = False
                FL[7] = False
            return npc
        if m in G.MEM_MN:
            self._generic_mem(m, ops, rd, wr, X)
            return npc
        if m == "ret":
            sh = self.__dict__.get("_shadow", [])
            if sh:
                return sh.pop()
            raise VMExit("ret")
        if m == "csel":
            wr(p[0], rd(p[1]) if fget(p[3]) else rd(p[2]))
            return npc
        if m == "cset":
            wr(p[0], 1 if fget(p[1]) else 0)
            return npc
        if m == "ccmp":
            if fget(p[3]):
                a = rd(p[0])
                b = rd(p[1])
                d = (a - b) & M64
                FL[0] = d == 0
                FL[1] = d != 0
                FL[6] = a >= b
                FL[7] = a < b
                FL[8] = a > b
                FL[9] = a <= b
            return npc
        if m == "b":
            t = pt(ops)
            if t is None:
                return npc
            if t == 0x100318:
                raise VMExit("exit-clean")
            return t
        if m.startswith("b."):
            if fget(m[2:]):
                t = pt(ops)
                if t is None:
                    return npc
                if t == 0x100318:
                    raise VMExit("exit-clean")
                return t
            return npc
        if m in ("cbz", "cbnz"):
            t = pt(p[-1])
            if t is not None:
                z = rd(p[0]) == 0
                if z == (m == "cbz"):
                    if t == 0x100318:
                        raise VMExit("exit-clean")
                    return t
            return npc
        if m in ("tbz", "tbnz"):
            t = pt(p[-1])
            bit = pt(p[1])
            if t is not None:
                b = ((rd(p[0]) >> bit) & 1) == 1
                if b == (m == "tbnz"):
                    if t == 0x100318:
                        raise VMExit("exit-clean")
                    return t
            return npc
        return npc                        # unmodelled -> no-op, as original

    def _gen_bl(self, t, X, mem, Q, IT, SR, EMIT, RND, NR, npc):
        raise RuntimeError("unexpected generic bl 0x%x" % (t or 0))

    def _generic_mem(self, m, ops, rd, wr, X):
        plan = _memplan(m, ops)
        if plan is None:
            return
        kind = plan[0]
        if kind == "imm":
            _, d, base, off, wb, size = plan
            bv = rd(base)
            addr = (bv + off) & M64
            mask = (M64 & ~7) if size == 8 else (M64 & ~3)
            if m in ("str", "stur", "strb"):
                mem[addr & (PM & (~7 if size == 8 else ~3))] = rd(d) & M64
            elif m == "stp":
                pass
            else:
                v = mem.get(addr & (PM & (~7 if size == 8 else ~3)), 0)
                wr(d, v)
                if m in ("ldrsw", "ldursw"):
                    v32 = v & M32
                    wr(d, v32 - (1 << 32) if v32 >= 0x80000000 else v32)
            if wb:
                wr(base, addr)
        elif kind == "pair":
            _, d1, d2, base, off, wb = plan
            bv = rd(base)
            addr = (bv + off) & M64
            if m == "stp":
                mem[addr & (PM & ~7)] = rd(d1) & M64
                mem[(addr + 8) & (PM & ~7)] = rd(d2) & M64
            else:
                wr(d1, mem.get(addr & (PM & ~7), 0))
                wr(d2, mem.get((addr + 8) & (PM & ~7), 0))
            if wb:
                wr(base, (bv + off) & M64)
                if off:
                    wr(base, addr)
        elif kind == "post":
            _, d, base, imm = plan
            bv = rd(base)
            wr(d, mem.get(bv & (PM & ~7), 0))
            wr(base, (bv + imm) & M64)
        else:
            _, d, base, ix, sh = plan
            bv = rd(base)
            iv = rd(ix) & M32
            addr = (bv + (iv << sh)) & M64
            wr(d, mem.get(addr & (PM & (~7 if d.strip().startswith("w") else ~3)), 0))
        if m == "ldrh":
            d = ops.split(",")[0].strip()
            if d in self.R:
                wr(d, rd(d) & 0xFFFF)


# ----------------------------------------------------------------------
if __name__ == "__main__":
    t0 = time.time()
    prepare(verbose=True, force="--rebuild" in sys.argv)
    print("prepare: %.2fs" % (time.time() - t0))