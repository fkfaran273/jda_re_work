"""vm_final.py — COMPLETE executor of the adj9 serializer with memory model.

Everything decoded in this thread, assembled:
  va_list frame (prologue at 0x100094):
    [x29-0x58..-0x38] = desc0..4 (x3..x7)   [x29+0x60..] = desc5..10 (stack)
    [x29-0x18] = gp marker (starts -40, +=8 per arg until 0)
    [x29-0x30] = advancing overflow ptr (init x29+0x60)
    [x29-0x28] = x29-0x30 (address of the advancing pointer)
    [x29-0x10] = stack canary
  field loop (0x100114): for desc i: sink = ctx[0x20+i*8]; EMIT(sink, j,
    BE(data[j])) for j in 0..len_dw
  queue program (0x100228..): stack-machine merge of streams into final layout
  header loop: 4x{PUSH rand; PUSH rand; XOR; EMIT} = the 16-B header

Stream objects {cap,data*,count,offs_len,offs*} are addressed by VA;
EMIT/LENQ/OUTLEN/PUSHS/POPS resolve their stream via x1.
Marker mode: field i dword j = marker (i<<24)|(j<<8)|0xA5 so the final
stream directly reveals the source of every dword.
"""
import sys, struct, re
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
from header_gen import Random3

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
INS = list(md.disasm(elf[0x100094:0x12aa48], 0x100094))
IDX = {i.address: k for k, i in enumerate(INS)}
# second executable range: output assembly fn (slice 17/33). Bounds via ELF.
try:
    from elf import ELF as _ELF

    _e = _ELF(LIB)
    _o = _e.vaddr_to_off(0x99000)
    _INS0 = list(md.disasm(_e.data[_o:_o + 0xBB548 - 0x99000], 0x99000))
    _base = len(INS)
    INS.extend(_INS0)
    for _k, _i in enumerate(_INS0):
        IDX[_i.address] = _base + _k
    try:
        _o3 = _e.vaddr_to_off(0x146000)
        _INS3 = list(md.disasm(_e.data[_o3:_o3 + 0x3000], 0x146000))
        _base3 = len(INS)
        INS.extend(_INS3)
        for _k, _i in enumerate(_INS3):
            IDX[_i.address] = _base3 + _k
    except Exception:
        pass
    _o = _e.vaddr_to_off(0xBB548)
    _INS2 = list(md.disasm(_e.data[_o:_o + 0xBCA30 - 0xBB548], 0xBB548))
    _base = len(INS)
    INS.extend(_INS2)
    for _k, _i in enumerate(_INS2):
        IDX[_i.address] = _base + _k
except Exception:
    pass

OP_PUSH, OP_POP, OP_EMIT, OP_LENQ, OP_OUTLEN = 0x147630, 0x147734, 0x146ed8, 0x147304, 0x1472e8
OP_PUSH2, OP_POP2, OP_ISEMPTY = 0x146470, 0x146478, 0x146474
OP_PUSHS, OP_POPS, OP_MKITER, OP_ITERNEXT = 0x147120, 0x147220, 0x146558, 0x146650
OP_RAND = 0x148d10
SUBR = {0xBA4A8, 0x9AFA4, 0x9C478, 0x9AD54,  # chain subroutines (slice 73+)
        0x147304, 0x146ED8, 0x147630, 0x147734,  # true queue ops (slice 78)
        0x146470, 0x146478, 0x1472E8}  # PUSH2/POP2/OUTLEN
SUBR_OPS = {0x147304, 0x146ED8, 0x147630, 0x147734,
            0x146470, 0x146478, 0x1472E8}
NOOPS = {0x146474}

def pt(s):
    try: return int(s.lstrip("#"), 16)
    except (ValueError, AttributeError): return None

DATAB = 0x5600000000  # descriptor data region base (fake)
PM = 0x0000FFFFFFFFFFFF  # 48-bit VA mask (strips MTE/heap tags, e.g. 0xb4..)
class StreamObj:
    def __init__(self, va, mem):
        self.va = va
        self.mem = mem
        self.data = []          # u32 growable (native: [va+0x18] -> u32 array)
        self.offs = [0]
        self.ro = False         # hydrated read-only: never write stocked memory
        self._acc = None        # RO streams track acc here (native +0x10)
        self.sync_struct()
    def sync_struct(self):
        if self.ro:
            return  # read-only hydration: never write back stocked memory
        # native stream struct (slice 10/13): +0x0 limit, +0x8 offs ptr,
        # +0x10 acc, +0x14 count, +0x18 data ptr, +0x28 nested
        # NOTE: acc (+0x10) and count (+0x14) are LIVE (merge EMITs / appends
        # update them); only initialize on first sync, never overwrite after.
        m = self.mem; va = self.va
        first = (va + 0x14) not in m
        daba = 0x5610000000 + (va & 0xFFFFFF)
        ofba = 0x5620000000 + (va & 0xFFFFFF)
        m[va + 0x00] = 0x7FFFFFFF
        m[va + 0x08] = ofba
        m[va + 0x28] = va
        if first:
            m[va + 0x10] = 0
            m[va + 0x14] = len(self.data)
        else:
            m[va + 0x14] = len(self.data)
        m[va + 0x18] = daba
        for j, v in enumerate(self.data):
            m[daba + 4 * j] = v
        for j, v in enumerate(self.offs):
            m[ofba + 4 * j] = v
    def base(self): return self.offs[-1]
    def emit(self, n, v, pc=0):
        v &= 0xFFFFFFFF
        n &= 0xFFFFFFFF
        if n > 0x100000:
            return
        acc0 = self.mem.get(self.va + 0x10, 0)
        if 0x10015C <= pc <= 0x100220:
            # FIELD path (field loop bulk load): data[n] = v (n==len appends)
            while len(self.data) <= n: self.data.append(0)
            self.data[n] = v
        elif (self.offs == [0] or not self.offs) and acc0 == 0 and n >= len(self.data):
            # APPEND path (fresh stream, wild index e.g. header XORs)
            self.data.append(v)
        else:
            # MERGE mode (0x1470d4..0x1470cc): idx = TOP + n; offs[idx] = v
            # (native malloc-grows; model caps at 4M entries ~16MB, drops beyond)
            top = self.data[-1] if self.data else 0
            idx = (top + n) & 0xFFFFFFFF
            if 0 <= idx < 4194304:
                while len(self.offs) <= idx: self.offs.append(0)
                self.offs[idx] = v
                if self.ro:
                    self._acc = (idx + 1) & 0xFFFFFFFF
                else:
                    self.mem[self.va + 0x10] = (idx + 1) & 0xFFFFFFFF
        self.sync_struct()
    def get(self, n):
        pos = self.base() + n
        return self.data[pos] if 0 <= pos < len(self.data) else 0
    def outlen(self):
        if self.ro:
            acc = self._acc if self._acc is not None else 0
        else:
            acc = self.mem.get(self.va + 0x10, 0) & 0xFFFFFFFF
        top = self.data[-1] if self.data else 0
        return (acc - top) & 0xFFFFFFFF

class Ex:
    """One descriptor: (len_dw, tag, data) with marker data."""
    def __init__(self, seed, descs, n_streams=16, shared_q=False):
        self._shared_q = shared_q
        self.R = {}
        self.F = {}
        self.mem = {}                     # fake memory (VA -> u64)
        self.streams = {}                  # stream VA -> StreamObj
        self.queues = {}                    # queue VA -> list
        self.iters = []                    # {arr,i,n}
        self.rnd = Random3(seed)
        self.nrand = 0
        self.steps = 0
        self.emit_trace = []
        # ---- fake addresses ----
        X29 = 0x5100000000
        self.X29 = X29
        CTX = 0x5200000000                 # x20: fields/ctx array
        W   = 0x5300000000                 # x19: writer status cell
        self.CTX, self.W = CTX, W
        self.R["x29"] = X29
        # ctx: [CTX+0]=queue ptr, [CTX+0x18]=queue2 ptr, [CTX+0x20+8i]=stream i
        QVA, Q2VA = 0x5400000000, 0x5400000100
        self.mem[CTX] = QVA
        self.mem[CTX + 0x18] = Q2VA
        self.QVA, self.Q2VA = QVA, Q2VA
        # every ctx slot [+8 .. +0xB0] = its own stream (the queue program
        # walks them via x26/[x26,#8]!); field sinks live at +0x20+8i
        for i in range(1, 24):
            sva = 0x5450000000 + i * 0x1000
            self.streams[sva] = StreamObj(sva, self.mem)
            self.mem[CTX + 8 * i] = sva
        self.MAIN = 0x5450001000    # [CTX+8]
        self.stream_of = {}
        for i in range(n_streams):
            sva = 0x5500000000 + i * 0x1000
            self.streams[sva] = StreamObj(sva, self.mem)
            self.stream_of[i] = sva
            self.mem[CTX + 0x20 + i * 8] = sva
        if getattr(self, "_shared_q", False):
            # EXPERIMENT: single shared value-queue for [CTX] and [CTX+0x18]
            self.mem[CTX] = QVA
            self.mem[CTX + 0x18] = QVA
            self.streams.pop(0x5450003000, None)
        # va_list frame
        self.mem[X29 - 0x18] = (2**64 - 40)     # gp = -40 (as u64; read as i32)
        self.mem[X29 - 0x30] = X29 + 0x60       # advancing ptr
        self.mem[X29 - 0x28] = X29 - 0x30
        self.mem[X29 - 0x10] = 0xDEADBEEF       # canary
        self.mem[X29 - 0x20] = 0
        # descriptors: 11 nodes
        for i, (lendl, tag, data) in enumerate(descs):
            nva = 0x5600000000 + i * 0x100
            dva = 0x5700000000 + i * 0x400
            self.mem[nva] = ((lendl << 2) | tag) | (0 << 32)
            self.mem[nva + 8] = dva
            for j in range(lendl):
                v = struct.unpack_from(">I", data, 4 * j)[0] if len(data) >= 4 * (j + 1) else 0
                self.mem[dva + 4 * j] = v        # store BE-decoded dword at aligned slot
            # place pointer into va slots
            if i < 5:
                self.mem[X29 - 0x58 + 8 * i] = nva
            else:
                self.mem[X29 + 0x60 + 8 * (i - 5)] = nva
        # register entry state
        self.R["x19"] = W
        self.R["x20"] = CTX
        self.R["x23"] = 0
        self.R["x22"] = 0
        self.R["w26"] = len(descs)
        self.R["x21"] = 0
        self.R["x26"] = 11   # arg count (w2)
        self.R["x28"] = CTX
        self.R["x27"] = 0
        self.R["x27"] = 0
        self.pc = 0x100114


    def set_reg(self, name, val):
        """write a register with true ARM64 x/w aliasing (NOT invalidation):
        xN <- V64 (wN = low32); wN <- V32 (xN = zero-extended)."""
        if name in ("wzr", "xzr", "sp"):
            if name == "sp": self.R["sp"] = val
            return
        if len(name) >= 2 and name[0] in "wx" and name[1:].isdigit():
            n = name[1:]
            if name[0] == "x":
                self.R["x" + n] = val & (2**64 - 1)
                self.R["w" + n] = val & 0xFFFFFFFF
            else:
                v32 = val & 0xFFFFFFFF
                self.R["w" + n] = v32
                self.R["x" + n] = v32
            return
        self.R[name] = val & (2**64 - 1)

    # ---- memory ----
    def ld(self, va, size=8):
        va &= PM
        va &= ~7 if size == 8 else ~3
        v = self.mem.get(va, 0)
        return v
    def st(self, va, v, size=8):
        va &= PM
        self.mem[va & (~7 if size == 8 else ~3)] = v & (2**64 - 1)
        if self.__dict__.get("_storelog") is not None and len(self._storelog) < 5000:
            self._storelog.append((hex(self.pc), hex(va & 0xFFFFFFFFFFFF)))

    # ---- byte access (heap mode; slice 74) ----
    def ldbyte(self, va):
        va &= 0x00FFFFFFFFFFFFFF
        w = self.mem.get(va & ~7, 0)
        return (w >> ((va & 7) * 8)) & 0xFF
    def stbyte(self, va, b):
        va &= 0x00FFFFFFFFFFFFFF
        a = va & ~7
        sh = (va & 7) * 8
        w = self.mem.get(a, 0)
        w = (w & ~(0xFF << sh)) | ((b & 0xFF) << sh)
        if w:
            self.mem[a] = w
        elif a in self.mem:
            del self.mem[a]

    def stream_for(self, va):
        va &= PM  # tagged (MTE) stream pointers resolve to the same object
        s = self.streams.get(va)
        if s is None:
            s = StreamObj(va, self.mem)
            self.streams[va] = s
        return s

    def run(self, max_steps=3_000_000):
        from collections import Counter
        self._pc_hist = Counter()
        while self.steps < max_steps:
            self.steps += 1
            self._pc_hist[self.pc] += 1
            pre = self.__dict__.get("_preload", {})
            if self.pc in pre and pre[self.pc]:
                qva = self.mem.get(self.CTX, 0)
                self.queues.setdefault(qva, [])[0:0] = list(pre[self.pc])
            fr = self.__dict__.get("_forcereg", {})
            if self.pc in fr:
                for rn, vv in fr[self.pc]:
                    self.set_reg(rn, vv)
            k = IDX.get(self.pc)
            if k is None: return "pc-out"
            if self.pc in (0xBBB14,):
                self.__dict__.setdefault("_bbb14", []).append(
                    tuple(self.R.get("x%d" % n, 0) for n in range(10)) + (self.R.get("x19", 0), self.R.get("x20", 0)))
            if self.pc == 0x9C4C0:
                self.__dict__.setdefault("_9c4c0", []).append(
                    tuple(self.R.get("x%d" % n, 0) for n in range(5)) + (self.R.get("x8", 0), self.R.get("x9", 0)))
                self.__dict__.setdefault("_b8a0", []).append(
                    (self.R.get("x10", 0), self.R.get("sp", 0),
                     self.mem.get((self.R.get("sp", 0) + 0x50) & ~7, -1)))
            if self.pc == 0xBB668 and len(self.__dict__.get("_hublog", [])) < 500:
                self.__dict__.setdefault("_hublog", []).append(self.R.get("x9", 0))
                seq = self.__dict__.get("_hubseq", [])
                if seq:
                    self.set_reg("x9", seq.pop(0))
                if len(self.__dict__.get("_hublog", [])) == 7:
                    self.__dict__["_roll7"] = list(self.__dict__.get("_roll", []))
                if len(self.__dict__.get("_hublog", [])) in (5, 6):
                    self.__dict__["_roll%d" % len(self.__dict__.get("_hublog", []))] = list(self.__dict__.get("_roll", []))
            if self.pc == 0xBA674 and len(self.__dict__.get("_mazelog", [])) < 1000:
                self.__dict__.setdefault("_mazelog", []).append(
                    (self.R.get("x8", 0), self.R.get("x9", 0), self.R.get("x20", 0)))
            if 0xBA000 <= self.pc < 0xBC000 and INS[k].mnemonic in ("ldr", "ldur", "ldp", "ldrb", "ldrsw", "ldrsh", "ldrsb"):
                self.__dict__.setdefault("_loads", []).append(self.pc)
            i = INS[k]
            m, ops = i.mnemonic, i.op_str
            npc = i.address + 4
            if m == "bl":
                t = pt(ops)
                w = self
                if len(w.__dict__.get("_calls", [])) < 2000:
                    w.__dict__.setdefault("_calls", []).append(
                        (hex(self.pc), hex(t) if t else ops,
                         tuple(w.R.get("x%d" % n, 0) & 0xFFFFFFFF for n in range(5)),
                         self.steps))
                if self.pc in w.__dict__.get("_substub", {}):
                    # stubbed call (live regs; slice 74): apply regs, skip.
                    retpc, regd = w.__dict__["_substub"][self.pc]
                    for rn, vv in regd.items():
                        if vv == "BUMP":
                            n = 0x400
                            va = w._heap[0]
                            w._heap[0] = va + n
                            w._heap[1][va] = n
                            vv = va
                        w.set_reg(rn, vv)
                    for off, vv in w.__dict__.get("_framefill", {}).get(self.pc, []):
                        if isinstance(vv, list):
                            vv = vv.pop(0) if vv else 0
                        a = (w.R.get("x29", 0) + off) & (2**64 - 1)
                        w.st(a, vv, 4 if off & 4 else 8)
                    w.__dict__.setdefault("_stublog", []).append(hex(self.pc))
                    npc = retpc
                elif (t in SUBR and t in IDX and
                      (t not in SUBR_OPS or w.__dict__.get("_truesub"))):
                    # true subroutine call (assembly chain always, queue ops
                    # opt-in via _truesub; slice 73/78): shadow-stack, jump.
                    w.__dict__.setdefault("_shadow", []).append(npc)
                    npc = t
                elif t in (OP_PUSH, OP_PUSH2):
                    qva = w.R.get("x1", 0)
                    w.queues.setdefault(qva, []).insert(0, w.R.get("w2", 0) & 0xFFFFFFFF)
                    w.__dict__.setdefault("_qlog", []).append(
                        (hex(self.pc), "PUSH", hex(qva & 0xFFFF), w.R.get("w2", 0) & 0xFFFFFFFF, len(w.queues[qva])))
                elif t in (OP_POP, OP_POP2):
                    qva = w.R.get("x1", 0)
                    # NOTE: native POP returns w0 only; w21 is set explicitly
                    # by mov sites. (A prior revision saved prev-w0 into w21
                    # here; it corrupted eor chains via x0-write aliasing.)
                    forced = False
                    if "_force_val" in w.__dict__:
                        fv = w.__dict__["_force_val"]
                        if isinstance(fv, dict):
                            if self.pc in fv and fv[self.pc]:
                                w.set_reg("w0", fv[self.pc].pop(0))
                                forced = True
                        elif self.pc == 0x100570:
                            forced = True
                            if isinstance(fv, list):
                                w.set_reg("w0", fv.pop(0))
                                if not fv:
                                    w.__dict__.pop("_force_val")
                            else:
                                w.set_reg("w0", fv)
                                if not w.__dict__.get("_force_persist"):
                                    w.__dict__.pop("_force_val")
                    if not forced:
                        if w.queues.get(qva):
                            w.set_reg("w0", w.queues[qva].pop(0))
                        else:
                            w.mem.__setitem__(w.R.get("x19", 0), 3)
                            w.set_reg("w0", 0)
                    w.__dict__.setdefault("_qlog", []).append(
                        (hex(self.pc), "POP", hex(qva & 0xFFFF), w.R.get("w0", 0), len(w.queues.get(qva, []))))
                elif t == OP_EMIT:
                    s = w.stream_for(w.R.get("x1", 0))
                    n = w.R.get("w2", 0); v = w.R.get("w3", 0)
                    s.emit(n, v, self.pc)
                    w.emit_trace.append((s.va, n, v))
                    if len(w.__dict__.get("_slog", [])) < 400:
                        w.__dict__.setdefault("_slog", []).append(
                            (hex(self.pc), "EMIT", hex(s.va & 0xFFFFF)))
                elif t == OP_LENQ:
                    s = w.stream_for(w.R.get("x0", 0))
                    n = w.R.get("w1", 0) & 0xFFFFFFFF
                    if s.data:
                        top = s.data[-1]
                    else:
                        top = 0
                    idx = (top + n) & 0xFFFFFFFF
                    # offs[TOP+n] if in range else data fallback (slice-10 contract)
                    if 0 <= idx < len(s.offs):
                        v = s.offs[idx]
                    elif s.data and 0 <= n < len(s.data):
                        v = s.data[n]
                    else:
                        v = 0
                    w.set_reg("w0", v)
                    if len(w.__dict__.get("_slog", [])) < 400:
                        w.__dict__.setdefault("_slog", []).append(
                            (hex(self.pc), "LENQ", hex(s.va & 0xFFFFF),
                             "top=%08x" % (s.data[-1] if s.data else 0), "n=%d" % n,
                             "idx=%08x" % idx, "v=%08x" % v))
                elif t == OP_OUTLEN:
                    s = w.stream_for(w.R.get("x0", 0))
                    acc = w.mem.get(s.va + 0x10, 0) & 0xFFFFFFFF
                    top = s.data[-1] if s.data else 0
                    w.set_reg("w0", (acc - top) & 0xFFFFFFFF)
                elif t == OP_PUSHS:
                    s = w.stream_for(w.R.get("x1", 0))
                    s.offs.append(w.R.get("w1", 0) & 0xFFFFFFFF)
                elif t == OP_POPS:
                    s = w.stream_for(w.R.get("x1", 0))
                    if len(s.offs) > 1: s.offs.pop()
                elif t == OP_MKITER:
                    nva = 0x5800000000 + (w.__dict__.get("_nit", 0)) * 0x100
                    w._nit = w.__dict__.get("_nit", 0) + 1
                    w.iters.append({"va": nva, "i": 0, "n": w.R.get("w2", 0)})
                    w.set_reg("w0", nva)
                    w.__dict__.setdefault("_mkiter", []).append(
                        (hex(self.pc), w.R.get("w2", 0)))
                elif t == OP_ITERNEXT:
                    va = w.R.get("x0", 0)
                    it = None
                    for cand in w.iters:
                        if cand["va"] == va:
                            it = cand
                            break
                    if it is None and len(w.iters) == 1:
                        # native ITERNEXT takes the iterator OBJECT (double
                        # deref via [sp]); VA-registry match fails on the
                        # inner pointer. Single live iterator => it.
                        it = w.iters[0]
                    if it and it["i"] + 1 < it["n"]:
                        it["i"] += 1
                        w.set_reg("w0", 1)
                    else:
                        if it: w.iters.remove(it)
                        w.set_reg("w0", 0)
                elif t == OP_ISEMPTY:
                    qva = w.R.get("x0", 0) or w.R.get("x1", 0)
                    w.set_reg("w0", 1 if not w.queues.get(qva) else 0)
                elif t == OP_RAND:
                    w.set_reg("w0", w.rnd.next() & 0xFFFFFFFF)
                    w.nrand += 1
                elif t in NOOPS:
                    pass
                elif t in (0x14784c, 0x147a20, 0x147a18):
                    # CAP(q, k): native routes on count-vs-k through an opaque
                    # maze; the PUSH exit pushes live R[x21] (slice 45). Model:
                    # pad with live x21 when top is out-of-index-range.
                    qva = w.R.get("x1", 0)
                    q = w.queues.setdefault(qva, [])
                    top = q[0] if q else None
                    if top is None or (top & 0xFFFFFFFF) >= 0x10000:
                        q.insert(0, w.R.get("x21", 0) & 0xFFFFFFFF)
                # stack_chk / free / calloc etc: no-op (legacy). Heap mode
                # (live replay, slice 74): real bump allocator + byte ops.
                elif t in (0x148B10, 0x148B90) and w.__dict__.get("_heap") is not None:
                    n = w.R.get("x0", 0)
                    if t == 0x148B90:
                        n *= w.R.get("x1", 0)
                    n = (n + 15) & ~15
                    if n > 0x100000:
                        w.__dict__.setdefault("_bigalloc", []).append((hex(self.pc), hex(n)))
                        n = 0x100000
                    va = w._heap[0]
                    w._heap[0] = va + max(n, 16)
                    w._heap[1][va] = max(n, 16)
                    w.set_reg("x0", va)
                elif t == 0x148BA0 and w.__dict__.get("_heap") is not None:
                    d, s, n = (w.R.get("x%d" % i, 0) & 0x00FFFFFFFFFFFFFF for i in range(3))
                    if n > 0x100000:
                        w.__dict__.setdefault("_bigalloc", []).append((hex(self.pc), hex(n)))
                        n = 0x100000
                    for k in range(n):
                        w.stbyte(d + k, w.ldbyte(s + k))
                elif t == 0x148A20 and w.__dict__.get("_heap") is not None:
                    d = w.R.get("x0", 0) & 0x00FFFFFFFFFFFFFF
                    w2, n = w.R.get("x1", 0) & 0xFF, w.R.get("x2", 0)
                    for k in range(n):
                        w.stbyte(d + k, w2)
                elif t == 0x148C80 and w.__dict__.get("_heap") is not None:
                    # realloc(ptr, size): bump new, copy min(old,new).
                    old = w.R.get("x0", 0) & 0x00FFFFFFFFFFFFFF
                    n = (w.R.get("x1", 0) + 15) & ~15
                    if n > 0x100000:
                        w.__dict__.setdefault("_bigalloc", []).append((hex(self.pc), hex(n)))
                        n = 0x100000
                    va = w._heap[0]
                    w._heap[0] = va + max(n, 16)
                    w._heap[1][va] = max(n, 16)
                    oldn = w._heap[1].get(old, 0)
                    for k in range(min(oldn, max(n, 16))):
                        w.stbyte(va + k, w.ldbyte(old + k))
                    w.set_reg("x0", va)
                elif t == 0x148CE0 and w.__dict__.get("_heap") is not None:
                    s = w.R.get("x0", 0) & 0x00FFFFFFFFFFFFFF
                    n = 0
                    while w.ldbyte(s + n) != 0 and n < 0x10000:
                        n += 1
                    w.set_reg("x0", n)
            elif m == "blr":
                # indirect call (JNI through tables, callbacks): log args,
                # treat as no-op returning 0 (mapping runs; slice 69).
                # _blrret override {pc: value} for live replay (slice 73+).
                self.__dict__.setdefault("_calls", []).append(
                    (hex(self.pc), "blr:" + ops.split()[0],
                     tuple(self.R.get("x%d" % n, 0) & 0xFFFFFFFF for n in range(9))))
                ov = self.__dict__.get("_blrret", {})
                self.set_reg("x0", ov.get(self.pc, 0))
            elif m == "csel":
                p = [x.strip() for x in ops.split(",")]
                self.set_reg(p[0], self.R.get(p[1], 0) if self.F.get(p[3], False)
                             else self.R.get(p[2], 0))
            elif m == "cset":
                p = [x.strip() for x in ops.split(",")]
                self.set_reg(p[0], 1 if self.F.get(p[1], False) else 0)
            elif m == "ccmp":
                # ccmp Xn, #imm, #nzcv, cond: if cond true, set flags as cmp
                p = [x.strip() for x in ops.split(",")]
                if self.F.get(p[3], False):
                    a = self.val(p[0]); b = self.val(p[1])
                    d = (a - b) & (2**64 - 1); s = a - b
                    self.F.update({"eq": d == 0, "ne": d != 0,
                                   "hs": a >= b, "lo": a < b,
                                   "hi": a > b, "ls": a <= b})
            elif m in ("mov", "movz"):
                d, s = [p.strip() for p in ops.split(",", 1)]
                v = self.val(s)
                self.set_reg(d, v)
            elif m == "movk":
                mm = re.match(r"^(\w+),#(0x[0-9a-f]+|\d+)(?:,lsl#(\d+))?", ops.replace(" ", ""))
                if mm:
                    d, imm, sh = mm.group(1), int(mm.group(2), 0), int(mm.group(3) or 0)
                    self.set_reg(d, (self.R.get(d, 0) & ~(0xFFFF << sh)) | ((imm & 0xFFFF) << sh))
            elif m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr", "rev", "rev16", "neg", "mvn"):
                p = [x.strip() for x in ops.split(",")]
                a = self.val(p[1]); b = self.val(p[2]) if len(p) > 2 else 0
                if len(p) > 3:
                    sh = p[3].replace(" ", "")
                    mm2 = re.match(r"(lsl|lsr|uxtw|sxtw)#(\d+)", sh)
                    if mm2:
                        k = int(mm2.group(2))
                        kind = mm2.group(1)
                        if kind == "lsl": b = (b << k) & (2**64 - 1)
                        elif kind == "lsr": b = (b >> k) & (2**64 - 1)
                        elif kind in ("uxtw", "sxtw"): b = ((b & 0xFFFFFFFF) << k) & (2**64 - 1)
                # ldp-style with writeback handled in ldr/ldp; here pure ALU
                if m == "add": v = (a + b) & (2**64 - 1)
                elif m == "sub": v = (a - b) & (2**64 - 1)
                elif m == "eor": v = a ^ b
                elif m == "and": v = a & b
                elif m == "orr": v = a | b
                elif m == "mul": v = (a * b) & (2**64 - 1)
                elif m == "lsl": v = (a << b) & (2**64 - 1)
                elif m == "lsr": v = (a >> b) & (2**64 - 1)
                elif m == "rev": v = int.from_bytes((a & 0xFFFFFFFF).to_bytes(4, "little"), "big")
                elif m == "rev16": v = ((a & 0xFFFF) << 16) | ((a >> 16) & 0xFFFF)
                elif m == "neg": v = (-a) & (2**64 - 1)
                elif m == "mvn": v = ~a & (2**64 - 1)
                self.set_reg(p[0], v)
                # '!' writeback forms are ldr/str; adds with shift lsl #3 for idx
            elif m == "lsr":
                pass
            elif m in ("cmp", "cmn", "tst"):
                p = [x.strip() for x in ops.split(",")]
                a = self.val(p[0]); b = self.val(p[1]) if len(p) > 1 else 0
                is32 = p[0].lstrip().startswith("w") if p else False
                if is32:
                    a &= 0xFFFFFFFF; b &= 0xFFFFFFFF
                    if m == "cmn":
                        r = a + b; d = r & 0xFFFFFFFF
                        C = r > 0xFFFFFFFF; Z = d == 0; N = (d >> 31) & 1
                        V = ((~(a ^ b) & (a ^ d)) >> 31) & 1
                    elif m == "cmp":
                        r = a - b; d = r & 0xFFFFFFFF
                        C = a >= b; Z = d == 0; N = (d >> 31) & 1
                        V = (((a ^ b) & (a ^ d)) >> 31) & 1
                    else:
                        d = a & b; C = False; Z = d == 0; N = (d >> 31) & 1; V = False
                    self.F = {"eq": Z, "ne": not Z,
                              "lt": N != V, "ge": N == V, "gt": (not Z) and (N == V), "le": Z or (N != V),
                              "hs": C, "lo": not C, "hi": C and not Z, "ls": (not C) or Z}
                    self.pc = npc
                    self.__dict__.setdefault("_roll", []).append(self.pc)
                    if len(self._roll) > 60: del self._roll[:30]
                    continue
                if m == "cmn": d = (a + b) & (2**64 - 1); s = a + b
                elif m == "tst": d = a & b; s = d
                else: d = (a - b) & (2**64 - 1); s = a - b
                self.F = {"eq": d == 0, "ne": d != 0,
                          "lt": s < 0, "ge": s >= 0, "gt": s > 0, "le": s <= 0,
                          "hs": d >= 0 if m != "cmn" else True,
                          "lo": d < 0 if m != "cmn" else False,
                          "hi": d > 0, "ls": d <= 0}
                # for hs/lo/hi/ls use unsigned semantics of a vs b
                if m == "cmp":
                    self.F["hs"] = a >= b; self.F["lo"] = a < b
                    self.F["hi"] = a > b; self.F["ls"] = a <= b
                if m == "cmn":
                    r = (a + b) & (2**64 - 1)
                    self.F["hs"] = r >= b; self.F["hi"] = r > b
            elif m == "b":
                t = pt(ops)
                if t is None: return "bad-b"
                if t == 0x100318: return "exit-clean"
                npc = t
            elif m.startswith("b."):
                cond = m[2:]
                if self.F.get(cond, False):
                    t = pt(ops)
                    if t is None: return "bad-bc"
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "cbz":
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1])
                if self.val(p[0]) == 0 and t is not None:
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "cbnz":
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1])
                if self.val(p[0]) != 0 and t is not None:
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "tbz":
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1]); bit = pt(p[1])
                if not (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318: return "exit-clean"
                        npc = t
            elif m == "tbnz":
                p = [x.strip() for x in ops.split(",")]
                t = pt(p[-1]); bit = pt(p[1])
                if (self.val(p[0]) >> bit) & 1:
                    if t is not None:
                        if t == 0x100318: return "exit-clean"
                        npc = t
            elif m == "ret":
                sh = self.__dict__.get("_shadow", [])
                if sh:
                    npc = sh.pop()
                else:
                    return "ret"
            elif m in ("ldr", "ldur", "str", "stur", "ldp", "stp", "ldrsb", "ldrsw", "ldursw", "ldrb", "strb", "ldrsh"):
                self.mem_op(i)
            elif m in ("mrs",):
                self.R[i.op_str.split(",")[0].strip()] = 0x1000
            elif m in ("stp",):
                pass
            self.pc = npc
            self.__dict__.setdefault("_roll", []).append(self.pc)
            if len(self._roll) > 60: del self._roll[:30]
            if len(self.emit_trace) == 300:
                self.__dict__["_runaway_path"] = list(self._roll)
            if self.pc == 0x100120:
                self.__dict__.setdefault("_t120", []).append(self.R.get("x8"))
            if self.pc == 0x10014c:
                self.__dict__.setdefault("_t14c", []).append((self.R.get("x8"), self.R.get("x27")))
        return "steps"

    def val(self, s):
        s = s.strip()
        if s in ("wzr", "xzr", "sp"): return self.R.get("sp", 0) if s == "sp" else 0
        if s.startswith("#"): return pt(s) or 0
        if s in self.R: return self.R[s]
        # xN <-> wN aliasing
        if len(s) >= 2 and s[0] in "wx" and s[1:].isdigit():
            other = ("w" if s[0] == "x" else "x") + s[1:]
            if other in self.R:
                v = self.R[other]
                return v & 0xFFFFFFFF if s[0] == "w" else v
        # register + shift forms like 'w0, uxtw #3' handled by caller
        base = s.split(",")[0].strip()
        if base in self.R:
            v = self.R[base]
            mm = re.search(r"(uxtw|sxtw|lsl) #(\d+)", s)
            if mm:
                sh = int(mm.group(2))
                if mm.group(1) == "lsl": v = (v << sh) & (2**64 - 1)
                else: v = (v & 0xFFFFFFFF) << sh if mm.group(1) == "uxtw" else v
            return v
        try: return int(s, 0)
        except ValueError: return 0

    def mem_op(self, i):
        m, ops = i.mnemonic, i.op_str
        # parse: ldr Xt, [Xn{, #imm}{, ...}] (+ writeback !)
        mm = re.match(r"^([wx]\d+|\w+\d*),\[([wx]\d+|sp)(?:,(#?[-0-9x]+))?\](!?)", ops.replace(" ", ""))
        if not mm:
            # stp/ldp pair
            mm2 = re.match(r"^(\w+),(\w+),\[([wx]\d+|sp)(?:,(#?-?[\dx]+))?\](!?)", ops.replace(" ", ""))
            if mm2 and m in ("stp", "ldp"):
                d1, d2, base, imm, wb = mm2.group(1), mm2.group(2), mm2.group(3), mm2.group(4), mm2.group(5)
                bv = self.R.get(base, 0)
                off = int(imm.lstrip('#'), 0) if imm else 0
                addr = (bv + off) & (2**64 - 1)
                if m == "stp":
                    self.st(addr, self.R.get(d1, 0))
                    self.st(addr + 8, self.R.get(d2, 0))
                else:
                    self.set_reg(d1, self.ld(addr))
                    self.set_reg(d2, self.ld(addr + 8))
                if wb == "!":
                    self.set_reg(base, (bv + off) & (2**64 - 1))
                    # post/pre semantics: '!' pre-index: base += off
                    if off: self.set_reg(base, addr)
                return
            # ldr Xt, [Xn, Xm{, lsl #k}] indexed
            mm3 = re.match(r"^(\w+),\[(\w+)\],(#?-?[\dx]+)$", ops.replace(" ", ""))
            if mm3:   # post-index
                d, base, imm = mm3.group(1), mm3.group(2), int(mm3.group(3), 0)
                bv = self.R.get(base, 0)
                self.set_reg(d, self.ld(bv))
                self.set_reg(base, (bv + imm) & (2**64 - 1))
                return
            mm4 = re.match(r"^(\w+),\[(\w+),(\w+)(?:,(uxtw|lsl)#(\d+))?\]", ops.replace(" ", ""))
            if mm4:   # register-indexed
                d, base, idx, _, sh = mm4.group(1), mm4.group(2), mm4.group(3), mm4.group(4), int(mm4.group(5) or 0)
                bv = self.R.get(base, 0)
                iv = self.R.get(idx, 0) & 0xFFFFFFFF
                addr = (bv + (iv << sh)) & (2**64 - 1)
                v = self.ld(addr, 4 if d.startswith("w") else 8)
                self.set_reg(d, v)
                return
            return
        d, base, imm, wb = mm.group(1), mm.group(2), mm.group(3), mm.group(4)
        imm = imm.strip() if imm else "0"
        try:
            off = int(imm.replace("#", ""), 0)
        except ValueError:
            off = 0
        if off is None: off = 0
        bv = self.R.get(base, 0)
        addr = (bv + off) & (2**64 - 1)
        size = 4 if (d.startswith("w") or m in ("ldrb", "strb", "ldrsw")) else 8
        if m in ("str", "stur", "strb"):
            self.st(addr, self.R.get(d, 0), 4 if m == "strb" else size)
        elif m in ("stp",):
            pass
        else:
            v = self.ld(addr, 8 if size == 8 else 4)
            self.set_reg(d, v)
            if m in ("ldrsw", "ldursw"):
                v32 = v & 0xFFFFFFFF
                self.set_reg(d, v32 - 2**32 if v32 >= 2**31 else v32)
        if wb == "!":
            self.set_reg(base, addr)

def run_markers(seed):
    """descriptors with marker data: field i dword j = (i<<20)|(j<<4)|0xA5"""
    descs = []
    for i, lendl in enumerate((36, 0, 1, 1, 8, 1, 1, 1, 4, 5, 4)):
        data = b"".join(struct.pack(">I", (i << 20) | (j << 4) | 0xA5) for j in range(lendl))
        descs.append((lendl, 0, data))
    ex = Ex(seed, descs)
    status = ex.run()
    return ex, status

if __name__ == "__main__":
    ex, status = run_markers(seed=1789072139)
    print("status:", status, "steps:", ex.steps, "nrand:", ex.nrand)
    print("streams:")
    for va, s in sorted(ex.streams.items()):
        if s.data:
            idx = (va - 0x5500000000) // 0x1000 if va >= 0x5500000000 else (va - 0x5450000000) // 0x1000
            print("  stream[%d] (ctx+%#x): %d dwords" % (idx, 0x20 + idx * 8, len(s.data)))
            print("    %s" % " ".join("%08x" % x for x in s.data[:44]))
    print("emit trace (first 40):", ex.emit_trace[:40])
    print("pc hotspot:", ex._pc_hist.most_common(8))
    from collections import Counter
    c = Counter((e[0]) for e in ex.emit_trace)
    print("emits per stream:", dict(c))
