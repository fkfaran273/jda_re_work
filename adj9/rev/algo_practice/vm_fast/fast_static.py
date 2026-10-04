"""fast_static.py — the block interpreter backed by the STATIC block module.

Identical semantics to fin_vm2_fast.FinEx (same setup, same state write-back);
only the dispatch table comes from vm_blocks_static.make() instead of the
exec()'d/marshalled blocks.  This is the variant a native compiler can turn
into C.
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
from vmgen import M32, M64, PM, VMExit                          # noqa: E402

import fin_vm2 as REF                                         # noqa: E402
import vm_final as V                                         # noqa: E402
from fin_vm2_fast import FinEx as _DynFinEx, MemDict            # noqa: E402
from vm_blocks_static import make as _make_blocks              # noqa: E402


class FinEx(_DynFinEx):
    """Same as fin_vm2_fast.FinEx but with a statically compiled block table."""

    @staticmethod
    def prepare():
        G.TRACE = False
        t, _sig = G.load_tables()
        G.blocks(t["FAST"], t["PC"])          # warm the cache, ignore result
        return 0.0

    def run(self, max_steps=4_000_000):
        R = self.R
        mem = self.mem
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
        VD = R
        EMIT = self.emit_trace
        Q = self.queues
        IT = self.iters
        SR = self.streams
        RND = self.rnd
        NR = [0]
        SH = self.__dict__.setdefault("_shadow", [])
        self = self

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
                s = SR[va] = REF.FinStream(va)
            n = X[2]
            v = X[3]
            s.emit(n, v)
            EMIT.append((s.va, n & M32, v & M32))

        def LENQ():
            va = X[0] & PM
            s = SR.get(va)
            if s is None:
                s = SR[va] = REF.FinStream(va)
            X[0] = s.lenq(X[1]) & M32

        def OUTLEN():
            va = X[0] & PM
            s = SR.get(va)
            if s is None:
                s = SR[va] = REF.FinStream(va)
            X[0] = s.outlen() & M32

        def PUSHS():
            va = X[1] & PM
            s = SR.get(va)
            if s is None:
                s = SR[va] = REF.FinStream(va)
            s.pushs()

        def POPS():
            va = X[1] & PM
            s = SR.get(va)
            if s is None:
                s = SR[va] = REF.FinStream(va)
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
            return self._generic(m, ops, npc, X, FL, mem, Q, IT, SR, EMIT,
                                 RND, NR)

        BPM = _make_blocks(X, mem, FL, VD, EMIT, Q, IT, SR, RND, NR, SH,
                           VMExit, PUSH, POP, EMIT_, LENQ, OUTLEN, PUSHS,
                           POPS, MKITER, ITERNEXT, ISEMPTY, RAND_, CAP_SWAP,
                           CAP_PUSH0, CAP_PUSH, GEN, self, None)

        pc = self.pc
        steps = 0
        status = "steps"
        try:
            while steps < max_steps:
                steps += 1
                pc = BPM[pc]()
        except VMExit as e:
            status = e.args[0]
        except KeyError:
            status = "pc-out"
            self.__dict__["_bad_pc"] = pc

        for n in range(31):
            v = X[n]
            R["x%d" % n] = v & M64
            R["w%d" % n] = v & M32
        R["sp"] = X[31] & M64
        F = self.F
        F.clear()
        from vmgen import COND
        for i, c in enumerate(COND):
            F[c] = FL[i]
        self.pc = pc
        self.steps = steps
        self.nrand = NR[0]
        return status


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(REV, "creditsea"))
    import testbed as TB
    import desc10_58 as LAW
    s = TB.mine_log()[0]
    dec = TB.decode(s["blob"])
    d0, d4, d2, _ = TB.region_parts(dec, s["second"])
    raw, _p = LAW.claims_for_law_58(s["val"], "session")
    ex = FinEx(int(s["second"]), TB.build_descs(s["second"], raw, d0, d4, d2))
    t0 = time.time()
    st = ex.run(max_steps=60_000_000)
    print("static-blocks VM: status=%s steps=%d  %.2fs"
          % (st, ex.steps, time.time() - t0))
