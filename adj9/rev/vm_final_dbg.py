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

OP_PUSH, OP_POP, OP_EMIT, OP_LENQ, OP_OUTLEN = 0x147630, 0x147734, 0x146ed8, 0x147304, 0x1472e8
OP_PUSHS, OP_POPS, OP_MKITER, OP_ITERNEXT = 0x147120, 0x147220, 0x146558, 0x146650
OP_RAND = 0x148d10
NOOPS = {0x14784c, 0x147a20, 0x147a18, 0x146470, 0x146474, 0x146478}

def pt(s):
    try: return int(s.lstrip("#"), 16)
    except (ValueError, AttributeError): return None

class StreamObj:
    def __init__(self, va, mem):
        self.va = va
        self.mem = mem
        self.data = []          # u32 growable
        self.offs = [0]
    def base(self): return self.offs[-1]
    def emit(self, n, v):
        pos = self.base() + n
        if not (0 <= pos < 65536): return
        while len(self.data) <= pos: self.data.append(0)
        self.data[pos] = v & 0xFFFFFFFF
    def get(self, n):
        pos = self.base() + n
        return self.data[pos] if 0 <= pos < len(self.data) else 0
    def outlen(self):
        return len(self.data) - self.base()

class Ex:
    """One descriptor: (len_dw, tag, data) with marker data."""
    def __init__(self, seed, descs, n_streams=16):
        self.R = {}
        self.F = {}
        self.mem = {}                     # fake memory (VA -> u64)
        self.streams = {}                  # stream VA -> StreamObj
        self.queue = []                    # the value stack (queue semantics)
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
        self.stream_of = {}
        for i in range(n_streams):
            sva = 0x5500000000 + i * 0x1000
            self.streams[sva] = StreamObj(sva, self.mem)
            self.stream_of[i] = sva
            self.mem[CTX + 0x20 + i * 8] = sva
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
        """write a register, invalidating its x/w alias so val() reads fresh."""
        if name in ("wzr", "xzr", "sp"):
            if name == "sp": self.R["sp"] = val
            return
        if len(name) >= 2 and name[0] in "wx" and name[1:].isdigit():
            other = ("w" if name[0] == "x" else "x") + name[1:]
            self.R.pop(other, None)
        self.R[name] = val & (2**64 - 1)

    # ---- memory ----
    def ld(self, va, size=8):
        va &= ~7 if size == 8 else ~3
        v = self.mem.get(va, 0)
        return v
    def st(self, va, v, size=8):
        self.mem[va & (~7 if size == 8 else ~3)] = v & (2**64 - 1)

    def stream_for(self, va):
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
            k = IDX.get(self.pc)
            if k is None: return "pc-out"
            i = INS[k]
            m, ops = i.mnemonic, i.op_str
            npc = i.address + 4
            if m == "bl":
                t = pt(ops)
                w = self
                if t == OP_PUSH:
                    w.queue.insert(0, w.R.get("w2", 0) & 0xFFFFFFFF)
                elif t == OP_POP:
                    w.set_reg("w21", w.R.get("w0", 0))
                    w.set_reg("w0", w.queue.pop(0) if w.queue else 0)
                elif t == OP_EMIT:
                    s = w.stream_for(w.R.get("x1", 0))
                    n = w.R.get("w2", 0); v = w.R.get("w3", 0)
                    s.emit(n, v)
                    w.emit_trace.append(((s.va - 0x5500000000) // 0x1000, n, v))
                elif t == OP_LENQ:
                    s = w.stream_for(w.R.get("x1", 0))
                    w.set_reg("w0", s.get(w.R.get("w1", 0)))
                elif t == OP_OUTLEN:
                    s = w.stream_for(w.R.get("x0", 0))
                    w.set_reg("w0", s.outlen())
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
                elif t == OP_ITERNEXT:
                    va = w.R.get("x0", 0)
                    it = None
                    for cand in w.iters:
                        if cand["va"] == va:
                            it = cand
                            break
                    if it and it["i"] + 1 < it["n"]:
                        it["i"] += 1
                        w.set_reg("w0", 1)
                    else:
                        if it: w.iters.remove(it)
                        w.set_reg("w0", 0)
                elif t == OP_RAND:
                    w.set_reg("w0", w.rnd.next() & 0xFFFFFFFF)
                    w.nrand += 1
                elif t in NOOPS:
                    pass
                # stack_chk / free / calloc etc: no-op
            elif m in ("mov", "movz"):
                d, s = [p.strip() for p in ops.split(",", 1)]
                v = self.val(s)
                self.set_reg(d, v)
            elif m == "movk":
                mm = re.match(r"^(\w+), #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?", ops.replace(" ", ""))
                if mm:
                    d, imm, sh = mm.group(1), int(mm.group(2), 0), int(mm.group(3) or 0)
                    self.set_reg(d, (self.R.get(d, 0) & ~(0xFFFF << sh)) | ((imm & 0xFFFF) << sh))
            elif m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr", "rev", "rev16", "neg", "mvn"):
                p = [x.strip() for x in ops.split(",")]
                a = self.val(p[1]); b = self.val(p[2]) if len(p) > 2 else 0
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
                return "ret"
            elif m in ("ldr", "ldur", "str", "stur", "ldp", "stp", "ldrsb", "ldrsw", "ldursw", "ldrb", "strb", "ldrsh"):
                self.mem_op(i)
            elif m in ("mrs",):
                self.R[i.op_str.split(",")[0].strip()] = 0x1000
            elif m in ("stp",):
                pass
            self.pc = npc
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
            idx = (va - 0x5500000000) // 0x1000
            print("  stream[%d] (ctx+%#x): %d dwords" % (idx, 0x20 + idx * 8, len(s.data)))
            print("    %s" % " ".join("%08x" % x for x in s.data[:20]))
    print("emit trace (first 40):", ex.emit_trace[:40])
    print("pc hotspot:", ex._pc_hist.most_common(8))
    from collections import Counter
    c = Counter((e[0]) for e in ex.emit_trace)
    print("emits per stream:", dict(c))
