"""fin_vm2.py — corrected stream/queue semantics for the adj9 VM executor.

Everything here is decoded DIRECTLY from libsigner.so disassembly (this file's
companion analysis, 2026-09-12):

Native stream struct (x1 of EMIT/LENQ/PUSHS/POPS):
    +0x00 limit   offs-array capacity in ENTRIES (grows by 0x80 on demand)
    +0x08 offs*   content array: offs[TOP + n]
    +0x10 acc     write high-water mark (idx+1 of the furthest EMIT)
    +0x14 count   TOP-stack depth
    +0x18 data*   TOP stack (sections); TOP = data[count-1]

Ops (all verified from the OLLVM state machines):
  EMIT(w,x1=stream,w2=n,w3=v)  idx=TOP+n; grow offs to >idx (+0x80 entries);
                               offs[idx]=v; acc=max(acc, idx+1)
  LENQ(x0=stream,w1=n)         TOP+n < limit ? offs[TOP+n] : 0
  OUTLEN(x0=stream)            acc - TOP
  PUSHS(x0=writer,x1=stream)   data.append(acc)            (start next section)
  POPS(x0=writer,x1=stream)    acc=data[count-1]; count-=1  (rewind 1 section;
                               underflow -> writer=7)
  PUSH(x0=writer,x1=q,w2=v)    LIFO insert at head; calloc fail -> writer=2
  POP(x0=writer,x1=q)          head value or (underflow -> writer=3, return 0)
  CAP  0x147a20 (k=w2)         count<=k -> writer=4; else swap values of
                               head and node[k]
  CAP  0x14784c/0x147a18 (k)   count<=k -> writer=4; else PUSH a copy of
                               node[k]'s value   (0x147a18 = k:=0 wrapper)

The old vm_final.StreamObj stored field data in `data` and used data[-1] as
TOP — inverted vs native. FinStream is the exact model; FinEx runs the same
interpreter core with these ops. vm_final.py is NOT modified.
"""
import sys
import struct

sys.path.insert(0, ".")
import vm_final as V
from vm_final import INS, IDX, pt, PM, FAST, _split
from header_gen import Random3

OP_PUSH, OP_POP = 0x147630, 0x147734
OP_PUSH2, OP_POP2 = 0x146470, 0x146478   # tail-calls b PUSH / b POP (verified)
OP_EMIT, OP_LENQ, OP_OUTLEN = 0x146ed8, 0x147304, 0x1472e8
OP_PUSHS, OP_POPS = 0x147120, 0x147220
OP_MKITER, OP_ITERNEXT = 0x146558, 0x146650
OP_RAND = 0x148d10
OP_ISEMPTY = 0x146474
CAP_SWAPS = {0x147a20}
CAP_PUSHS = {0x14784c, 0x147a18}


class FinStream:
    """Exact native stream model."""

    __slots__ = ("va", "top", "offs", "acc", "limit")

    def __init__(self, va):
        self.va = va
        self.top = [0]        # data[] TOP stack, count = 1
        self.offs = {}        # sparse offs array
        self.acc = 0
        self.limit = 0        # offs capacity (entries)

    def emit(self, n, v):
        n &= 0xFFFFFFFF
        v &= 0xFFFFFFFF
        idx = (self.top[-1] + n) & 0xFFFFFFFF
        if idx >= self.limit:
            # native: realloc +0x80 entries, repeat (C->A loop) until idx<limit
            self.limit = ((idx // 0x80) + 1) * 0x80
        self.offs[idx] = v
        if idx >= self.acc:
            self.acc = (idx + 1) & 0xFFFFFFFF
        return idx

    def lenq(self, n):
        n &= 0xFFFFFFFF
        idx = (self.top[-1] + n) & 0xFFFFFFFF
        if idx < self.limit:
            return self.offs.get(idx, 0)
        return 0

    def outlen(self):
        return (self.acc - self.top[-1]) & 0xFFFFFFFF

    def pushs(self):
        self.top.append(self.acc)

    def pops(self):
        # POPS: acc = data[count-1] (old TOP); count -= 1; underflow -> 7
        if not self.top:
            return 7
        self.acc = self.top[-1]
        self.top.pop()
        return 0


class FinEx(V.Ex):
    """Ex with the corrected stream/queue ops (run() overridden)."""

    def __init__(self, seed, descs, n_streams=16, shared_q=False):
        # Descriptor #10 is a byte-oriented claim string and may have a
        # non-dword tail (the captures use 14 bytes).  The serializer's
        # descriptor node carries the NUL-padded dword count, not the
        # unpadded byte count.  Normalize here so direct FinEx callers and
        # capture replay have identical input semantics.
        # #7 is the logical (unpadded) #10 byte length.  A capture can still
        # contain a stale/nonzero #10 payload when #7 is zero (the
        # environment-value gate); in that case the VM must see an empty
        # #10, not the captured bytes.
        descs = list(descs)
        if len(descs) == 11 and len(bytes(descs[5][2])) >= 4:
            logical_d10_len = struct.unpack(">I", bytes(descs[5][2])[:4])[0]
            raw10 = bytes(descs[6][2])[:logical_d10_len]
            descs[6] = (0, descs[6][1], raw10)
        normalized = []
        for lendl, tag, data in descs:
            raw = bytes(data)
            padded = raw + b"\x00" * (-len(raw) % 4)
            normalized.append((max(int(lendl), len(padded) // 4), tag, padded))

        descs = normalized
        super().__init__(seed, descs, n_streams=n_streams, shared_q=shared_q)
        # iterators: dict {node_va: {"count": n, "next": va|None}} (native
        # MKITER/ITERNEXT push/pop nodes through a head cell in mem)
        self.iters = {}
        # replace every stream with the corrected model (same VAs)
        for va in list(self.streams.keys()):
            self.streams[va] = FinStream(va)
        # fix descriptor data words: native memory holds the RAW bytes; the
        # field loop does `ldr w8,[data]` (little-endian) + `rev w3,w8` to get
        # the BE dword. vm_final stored the BE-decoded dword -> double swap.
        #
        # Descriptor regions are not actually 0x400 bytes apart in the
        # capture: #10 is 1072 bytes (268 dwords), so the old 0x400 spacing
        # made its final dword overlap descriptor #7's region.  That turned
        # the first tail word into zero and diverged the claim/sink streams
        # at body word 12.  Give every descriptor a non-overlapping 0x1000
        # slot and update its node data pointer accordingly.
        for i, (lendl, tag, data) in enumerate(descs):
            nva = 0x5600000000 + i * 0x100
            dva = 0x5700000000 + i * 0x1000
            self.mem[nva + 8] = dva
            for j in range(lendl):
                v = struct.unpack_from("<I", data, 4 * j)[0] if len(data) >= 4 * (j + 1) else 0
                self.mem[dva + 4 * j] = v

    def stream_for(self, va):
        va &= PM
        s = self.streams.get(va)
        if s is None:
            s = FinStream(va)
            self.streams[va] = s
        return s

    # ---- CAP helpers ----
    def _q_nodes(self, qva):
        return self.queues.setdefault(qva, [])

    def cap_swap(self, qva, k):
        q = self.queues.setdefault(qva, [])
        if len(q) <= k:
            self.mem[self.R.get("x19", 0)] = 4
            return
        q[0], q[k] = q[k], q[0]          # swap head value with node[k] value

    def cap_push(self, qva, k):
        q = self.queues.setdefault(qva, [])
        if len(q) <= k:
            self.mem[self.R.get("x19", 0)] = 4
            return
        q.insert(0, q[k])                # push a copy of node[k]'s value

    def mem_op2(self, m, ops):
        super().mem_op2(m, ops)
        if m == "ldrh":
            d = ops.split(",")[0].strip()
            if d in self.R:
                self.set_reg(d, self.R[d] & 0xFFFF)

    def run(self, max_steps=4_000_000):
        R, F, mem = self.R, self.F, self.mem
        _hook = self.__dict__.get("_step_hook")
        _pclog = self.__dict__.get("_pc_log")
        _dbg = self.__dict__.get("_dbg164")
        _fast = not (_hook is not None or _pclog is not None
                     or _dbg is not None)
        _f = FAST
        while self.steps < max_steps:
            self.steps += 1
            if not _fast:
                if _hook is not None:
                    _hook(self)
                if _pclog is not None:
                    _pclog.append(self.pc)
            k = IDX.get(self.pc)
            if k is None:
                return "pc-out"
            if not _fast and self.pc == 0x100164 and _dbg is not None:
                _dbg.append((R.get("x21"), R.get("x22"), self.steps))
            if _fast:
                m, ops, npc = _f[k]
            else:
                i = INS[k]
                m, ops = i.mnemonic, i.op_str
                npc = i.address + 4
            if m == "bl":
                t = pt(ops)
                if t in (OP_PUSH, OP_PUSH2):
                    qva = R.get("x1", 0)
                    self.queues.setdefault(qva, []).insert(0, R.get("w2", 0) & 0xFFFFFFFF)
                    if self.__dict__.get("_qop_log") is not None:
                        self._qop_log.append(("PUSH", self.pc, qva & 0xFFFFFFFFFFFF,
                                              R.get("w2", 0) & 0xFFFFFFFF))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("PUSH", self.pc,
                                               qva & 0xFFFFFFFFFFFF,
                                               R.get("w2", 0) & 0xFFFFFFFF))
                elif t in (OP_POP, OP_POP2):
                    qva = R.get("x1", 0)
                    q = self.queues.get(qva)
                    if q:
                        R["w0"] = q.pop(0)
                        R["x0"] = R["w0"]
                    else:
                        mem[R.get("x19", 0)] = 3
                        R["w0"] = 0
                        R["x0"] = 0
                    if self.__dict__.get("_qop_log") is not None:
                        self._qop_log.append(("POP", self.pc, qva & 0xFFFFFFFFFFFF,
                                              R.get("w0", 0) & 0xFFFFFFFF))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("POP", self.pc,
                                               qva & 0xFFFFFFFFFFFF,
                                               R.get("w0", 0) & 0xFFFFFFFF))
                elif t == OP_EMIT:
                    s = self.stream_for(R.get("x1", 0))
                    n = R.get("w2", 0)
                    v = R.get("w3", 0)
                    s.emit(n, v)
                    self.emit_trace.append((s.va, n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                    if self.__dict__.get("_emit_pc") is not None:
                        self._emit_pc.append((self.pc, s.va, n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                    if self.__dict__.get("_emit_full") is not None:
                        self._emit_full.append((self.pc, s.va, s.top[-1],
                                                n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("E", self.pc, s.va, s.top[-1],
                                               n & 0xFFFFFFFF, v & 0xFFFFFFFF))
                elif t == OP_LENQ:
                    s = self.stream_for(R.get("x0", 0))
                    R["w0"] = s.lenq(R.get("w1", 0))
                    R["x0"] = R["w0"]
                    if self.__dict__.get("_lenq_log") is not None:
                        self._lenq_log.append((self.pc, s.va, R.get("w1", 0) & 0xFFFFFFFF,
                                               s.top[-1], R["w0"]))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("Q", self.pc, s.va,
                                               s.top[-1],
                                               R.get("w1", 0) & 0xFFFFFFFF,
                                               R["w0"] & 0xFFFFFFFF))
                elif t == OP_OUTLEN:
                    s = self.stream_for(R.get("x0", 0))
                    R["w0"] = s.outlen()
                    R["x0"] = R["w0"]
                elif t == OP_PUSHS:
                    s = self.stream_for(R.get("x1", 0))
                    if self.__dict__.get("_sp_log") is not None:
                        self._sp_log.append(("PUSHS", i.address, s.va, s.acc, list(s.top)))
                    s.pushs()
                elif t == OP_POPS:
                    s = self.stream_for(R.get("x1", 0))
                    if self.__dict__.get("_sp_log") is not None:
                        self._sp_log.append(("POPS", i.address, s.va, s.acc, list(s.top)))
                    err = s.pops()
                    if err:
                        mem[R.get("x19", 0)] = err
                elif t in CAP_SWAPS:
                    if self.__dict__.get("_cap_log") is not None:
                        q = self.queues.get(R.get("x1", 0), [])
                        self._cap_log.append(("SW", self.pc, len(q), R.get("w2", 0), list(q[:6])))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("SW", self.pc,
                                               R.get("x1", 0) & 0xFFFFFFFFFFFF,
                                               R.get("w2", 0) & 0xFFFFFFFF))
                    self.cap_swap(R.get("x1", 0), R.get("w2", 0) & 0xFFFFFFFF)
                elif t in CAP_PUSHS:
                    kk = 0 if t == 0x147a18 else (R.get("w2", 0) & 0xFFFFFFFF)
                    # 0x147a18 = thunk: mov w2,wzr; b 0x14784c  (CAP push, k:=0)
                    if self.__dict__.get("_cap_log") is not None:
                        q = self.queues.get(R.get("x1", 0), [])
                        self._cap_log.append(("PU", self.pc, len(q), kk, list(q[:6])))
                    if self.__dict__.get("_wire_log") is not None:
                        self._wire_log.append(("PU", self.pc,
                                               R.get("x1", 0) & 0xFFFFFFFFFFFF,
                                               kk))
                    self.cap_push(R.get("x1", 0), kk)
                elif t == OP_MKITER:
                    # native MKITER(x0=writer, x1=head_cell, w2=n):
                    #   node = calloc(1,16); node[0]=n; node[8]=[x1]; [x1]=node
                    #   (alloc failure -> [writer]=2; cannot happen here)
                    # The nodes form a LIFO list through the head cell, so
                    # nested iterators nest correctly.
                    cell = R.get("x1", 0) & PM
                    nva = 0x5800000000 + (self.__dict__.get("_nit", 0)) * 0x100
                    self._nit = self.__dict__.get("_nit", 0) + 1
                    self.iters[nva] = {"count": R.get("w2", 0) & 0xFFFFFFFF,
                                       "next": self.mem.get(cell)}
                    self.mem[cell] = nva
                    R["w0"] = nva
                    R["x0"] = nva
                elif t == OP_ITERNEXT:
                    # native ITERNEXT(x0=head_cell):
                    #   node = [x0]; w21 = node.count - 1; node.count = w21
                    #   if w21 == 0: [x0] = node.next; free(node)
                    #   return w21    (caller loops with cbnz while non-zero)
                    cell = R.get("x0", 0) & PM
                    nva = self.mem.get(cell)
                    node = self.iters.get(nva) if nva is not None else None
                    if node is None:
                        R["w0"] = 0
                        R["x0"] = 0
                    else:
                        c = (node["count"] - 1) & 0xFFFFFFFF
                        node["count"] = c
                        if c == 0:
                            self.mem[cell] = node["next"]
                            self.iters.pop(nva, None)
                        R["w0"] = c
                        R["x0"] = c
                elif t == OP_ISEMPTY:
                    qva = R.get("x0", 0) or R.get("x1", 0)
                    R["w0"] = 1 if not self.queues.get(qva) else 0
                    R["x0"] = R["w0"]
                elif t == OP_RAND:
                    R["w0"] = self.rnd.next() & 0xFFFFFFFF
                    R["x0"] = R["w0"]
                    self.nrand += 1
                else:
                    # unknown bl: log it loudly, treat as no-op
                    self.__dict__.setdefault("_unk_bl", set()).add(hex(t or 0))
                    R["w0"] = R.get("w0", 0)
            elif m == "blr":
                self.set_reg("x0", 0)
            elif m == "csel":
                p = _split(ops)
                self.set_reg(p[0], R.get(p[1], 0) if F.get(p[3], False)
                             else R.get(p[2], 0))
            elif m == "cset":
                p = _split(ops)
                self.set_reg(p[0], 1 if F.get(p[1], False) else 0)
            elif m == "ccmp":
                p = _split(ops)
                if F.get(p[3], False):
                    a = self.val(p[0]); b = self.val(p[1])
                    d = (a - b) & (2**64 - 1)
                    F.update({"eq": d == 0, "ne": d != 0,
                              "hs": a >= b, "lo": a < b,
                              "hi": a > b, "ls": a <= b})
            elif m in ("mov", "movz"):
                d, s = [p.strip() for p in ops.split(",", 1)]
                self.set_reg(d, self.val(s))
            elif m == "movk":
                import re
                mm = re.match(r"^(\w+),#(0x[0-9a-f]+|\d+)(?:,lsl#(\d+))?", ops.replace(" ", ""))
                if mm:
                    d, imm, sh = mm.group(1), int(mm.group(2), 0), int(mm.group(3) or 0)
                    self.set_reg(d, (R.get(d, 0) & ~(0xFFFF << sh)) | ((imm & 0xFFFF) << sh))
            elif m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr",
                       "rev", "rev16", "neg", "mvn", "udiv", "msub"):
                p = _split(ops)
                if m == "udiv":
                    a = self.val(p[1]); b = self.val(p[2])
                    a &= 0xFFFFFFFF; b &= 0xFFFFFFFF
                    v = (a // b) if b else 0
                    if p[0].startswith("w"):
                        v &= 0xFFFFFFFF
                    self.set_reg(p[0], v)
                    self.pc = npc
                    continue
                if m == "msub":
                    # msub Wd, Wn, Wm, Wa: Wd = Wa - Wn*Wm
                    a = self.val(p[1]); b = self.val(p[2]); c = self.val(p[3])
                    v = (c - a * b) & (2**64 - 1)
                    if p[0].startswith("w"):
                        v &= 0xFFFFFFFF
                    self.set_reg(p[0], v)
                    self.pc = npc
                    continue
                a = self.val(p[1]); b = self.val(p[2]) if len(p) > 2 else 0
                if len(p) > 3:
                    sh = p[3].replace(" ", "")
                    import re
                    mm2 = re.match(r"(lsl|lsr|uxtw|sxtw)#(\d+)", sh)
                    if mm2:
                        kk = int(mm2.group(2))
                        if mm2.group(1) == "lsl":
                            b = (b << kk) & (2**64 - 1)
                        elif mm2.group(1) == "lsr":
                            b = (b >> kk) & (2**64 - 1)
                        elif mm2.group(1) in ("uxtw", "sxtw"):
                            b = ((b & 0xFFFFFFFF) << kk) & (2**64 - 1)
                if m == "add":
                    v = (a + b) & (2**64 - 1)
                elif m == "sub":
                    v = (a - b) & (2**64 - 1)
                elif m == "eor":
                    v = a ^ b
                elif m == "and":
                    v = a & b
                elif m == "orr":
                    v = a | b
                elif m == "mul":
                    v = (a * b) & (2**64 - 1)
                elif m == "lsl":
                    v = (a << b) & (2**64 - 1)
                elif m == "lsr":
                    v = (a >> b) & (2**64 - 1)
                elif m == "rev":
                    v = int.from_bytes((a & 0xFFFFFFFF).to_bytes(4, "little"), "big")
                elif m == "rev16":
                    v = ((a & 0xFFFF) << 16) | ((a >> 16) & 0xFFFF)
                elif m == "neg":
                    v = (-a) & (2**64 - 1)
                elif m == "mvn":
                    v = ~a & (2**64 - 1)
                self.set_reg(p[0], v)
            elif m in ("cmp", "cmn", "tst"):
                p = _split(ops)
                a = self.val(p[0]); b = self.val(p[1]) if len(p) > 1 else 0
                is32 = p[0].lstrip().startswith("w") if p else False
                if is32:
                    a &= 0xFFFFFFFF; b &= 0xFFFFFFFF
                    if m == "cmn":
                        r = a + b; d = r & 0xFFFFFFFF
                        C = r > 0xFFFFFFFF; Z = d == 0; N = (d >> 31) & 1
                        Vv = ((~(a ^ b) & (a ^ d)) >> 31) & 1
                    elif m == "cmp":
                        r = a - b; d = r & 0xFFFFFFFF
                        C = a >= b; Z = d == 0; N = (d >> 31) & 1
                        Vv = (((a ^ b) & (a ^ d)) >> 31) & 1
                    else:
                        d = a & b; C = False; Z = d == 0; N = (d >> 31) & 1; Vv = False
                    F.clear(); F.update({"eq": Z, "ne": not Z,
                              "lt": N != Vv, "ge": N == Vv,
                              "gt": (not Z) and (N == Vv), "le": Z or (N != Vv),
                              "hs": C, "lo": not C, "hi": C and not Z,
                              "ls": (not C) or Z})
                    self.pc = npc
                    continue
                if m == "cmn":
                    d = (a + b) & (2**64 - 1); sg = a + b
                elif m == "tst":
                    d = a & b; sg = d
                else:
                    d = (a - b) & (2**64 - 1); sg = a - b
                F.clear(); F.update({"eq": d == 0, "ne": d != 0,
                          "lt": sg < 0, "ge": sg >= 0, "gt": sg > 0, "le": sg <= 0,
                          "hi": d > 0, "ls": d <= 0})
                if m == "cmp":
                    F["hs"] = a >= b; F["lo"] = a < b
                elif m == "cmn":
                    F["hs"] = True; F["lo"] = False
            elif m == "b":
                t = pt(ops)
                if t is None:
                    return "bad-b"
                if t == 0x100318:
                    return "exit-clean"
                npc = t
            elif m.startswith("b."):
                cond = m[2:]
                if F.get(cond, False):
                    t = pt(ops)
                    if t is None:
                        return "bad-bc"
                    if t == 0x100318:
                        return "exit-clean"
                    npc = t
            elif m == "cbz":
                p = _split(ops)
                t = pt(p[-1])
                if self.val(p[0]) == 0 and t is not None:
                    if t == 0x100318:
                        return "exit-clean"
                    npc = t
            elif m == "cbnz":
                p = _split(ops)
                t = pt(p[-1])
                if self.val(p[0]) != 0 and t is not None:
                    if t == 0x100318:
                        return "exit-clean"
                    npc = t
            elif m == "tbz":
                p = _split(ops)
                t = pt(p[-1]); bit = pt(p[1])
                if not (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318:
                            return "exit-clean"
                        npc = t
            elif m == "tbnz":
                p = _split(ops)
                t = pt(p[-1]); bit = pt(p[1])
                if (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318:
                            return "exit-clean"
                        npc = t
            elif m == "ret":
                sh = self.__dict__.get("_shadow", [])
                if sh:
                    npc = sh.pop()
                else:
                    return "ret"
            elif m in ("ldr", "ldur", "str", "stur", "ldp", "stp", "ldrsb",
                       "ldrsw", "ldursw", "ldrb", "strb", "ldrsh", "ldrh"):
                self.mem_op2(m, ops)
            elif m == "mrs":
                R[ops.split(",")[0].strip()] = 0x1000
            self.pc = npc
        return "steps"
