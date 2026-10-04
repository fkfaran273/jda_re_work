"""vm_exec.py — true PC-based executor of the adj9 serializer program.
Handles: real control flow (b/b.cond/cbz/cbnz with flags), the iterator
ops (MKITER/ITERNEXT), guards (cbnz w8 not taken — writer OK), the
PUSH/POP stack, EMIT/LENQ/OUTLEN/PUSHS/POPS on the stream, rand.

Ops with known semantics:
  PUSH(q,w2)  prepend node            0x147630
  POP(q)->w0  pop head; w21=old w0    0x147734
  EMIT(w,q,w2=n,w3=v) 0x146ed8  stream[base+n]=v (grow)
  LENQ(q,w1=n)->w0    0x147304  read stream[base+n]
  OUTLEN(w)->w0       0x1472e8  count - base
  PUSHS               0x147120  push section-start (w1 arg)
  POPS                0x147220  pop section-start
  MKITER(x0,x1,w2)    0x146558  iterator over array x1, count w2
  ITERNEXT(x0)->w0    0x146650  advance; 1=more,0=done
  RAND->w0            PLT 0x148d10
  CAP/OP7A20/OP7A18   0x14784c/0x147a20/0x147a18  count-checks (no-op on values)
"""
import sys, struct, re, json
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
from header_gen import Random3

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
PROG_LO, PROG_HI = 0x100094, 0x12aa48
INS = list(md.disasm(elf[PROG_LO:PROG_HI], PROG_LO))
IDX = {i.address: k for k, i in enumerate(INS)}

OP_PUSH, OP_POP, OP_EMIT, OP_LENQ, OP_OUTLEN = 0x147630, 0x147734, 0x146ed8, 0x147304, 0x1472e8
OP_PUSHS, OP_POPS, OP_MKITER, OP_ITERNEXT = 0x147120, 0x147220, 0x146558, 0x146650
OP_RAND = 0x148d10
NOOPS = {0x14784c, 0x147a20, 0x147a18, 0x146470, 0x146474, 0x146478, 0x148b90, 0x148a00}

def pt(s):
    try: return int(s.lstrip("#"), 16)
    except (ValueError, AttributeError): return None

class Exec:
    def __init__(self, fields, seed, trace_emit=True):
        self.R = {}                     # register file (w/x numeric)
        self.F = {}                     # flags: eq ne le lt ge gt hi lo hs ls
        self.stack = []
        self.s_data = []
        self.s_off = [0]
        self.iters = []                 # list of {arr, i, n}
        self.rnd = Random3(seed)
        self.fields = fields
        self.nrand = 0
        self.emit_log = []
        self.trace_emit = trace_emit
        self.steps = 0
        self.pc = 0x100114             # field loop head
        self.f_i = 0                    # field index
        self.f_j = 0                    # dword within field
        self.x20 = 0                    # queue obj (opaque)
        self.in_fieldloop = True

    # ---- helpers ----
    def base(self): return self.s_off[-1]
    def emit(self, n, v):
        pos = self.base() + n
        if 0 <= pos < 8192:
            while len(self.s_data) <= pos: self.s_data.append(0)
            self.s_data[pos] = v & 0xFFFFFFFF
            if self.trace_emit: self.emit_log.append((pos, v & 0xFFFFFFFF))
    def sget(self, n):
        pos = self.base() + n
        return self.s_data[pos] if 0 <= pos < len(self.s_data) else 0

    def run(self, max_steps=400000):
        # preload field loop vars: x23=0 (field idx), x26=count, x20=queue base
        self.R["x23"] = 0
        self.R["x26"] = len(self.fields)
        while self.steps < max_steps:
            self.steps += 1
            k = IDX.get(self.pc)
            if k is None: return "pc-out"
            i = INS[k]
            m, ops = i.mnemonic, i.op_str
            npc = i.address + 4
            # ---------- instruction dispatch ----------
            if m == "bl":
                t = pt(ops)
                if t == OP_PUSH:
                    self.stack.insert(0, self.R.get("w2", 0))
                elif t == OP_POP:
                    self.R["w21"] = self.R.get("w0", 0)
                    self.R["w0"] = self.stack.pop(0) if self.stack else 0
                elif t == OP_EMIT:
                    self.emit(self.R.get("w2", 0), self.R.get("w3", 0))
                elif t == OP_LENQ:
                    self.R["w0"] = self.sget(self.R.get("w1", 0))
                elif t == OP_OUTLEN:
                    self.R["w0"] = len(self.s_data) - self.base()
                elif t == OP_PUSHS:
                    v = self.R.get("w1", 0)
                    self.s_off.append(v if v else len(self.s_data))
                elif t == OP_POPS:
                    if len(self.s_off) > 1: self.s_off.pop()
                elif t == OP_MKITER:
                    arr = self.R.get("x1", 0)
                    cnt = self.R.get("w2", 0)
                    self.iters.append({"arr": arr, "i": 0, "n": cnt})
                    self.R["w0"] = 1
                elif t == OP_ITERNEXT:
                    it = self.iters[-1] if self.iters else None
                    if it and it["i"] + 1 < it["n"]:
                        it["i"] += 1
                        self.R["w0"] = 1
                    else:
                        if self.iters: self.iters.pop()
                        self.R["w0"] = 0
                elif t == OP_RAND:
                    self.R["w0"] = self.rnd.next() & 0xFFFFFFFF
                    self.nrand += 1
                elif t in NOOPS:
                    pass
                else:
                    # unknown call: log once, continue
                    self.R.setdefault("_unknown", set()).add(t)
            elif m in ("mov", "movz"):
                d, s = [p.strip() for p in ops.split(",", 1)]
                v = 0 if s in ("wzr", "xzr") else (self.R.get(s, 0) if s in self.R or s[:1] in ("w", "x") and s[1:].isdigit() else pt(s))
                if s.startswith("#"): v = pt(s)
                self.R[d] = v if v is not None else 0
            elif m == "movk":
                mm = re.match(r"^(\w+), #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?", ops.replace(" ", ""))
                if mm:
                    d, imm, sh = mm.group(1), int(mm.group(2), 0), int(mm.group(3) or 0)
                    cur = self.R.get(d, 0)
                    self.R[d] = (cur & ~(0xFFFF << sh)) | ((imm & 0xFFFF) << sh)
            elif m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr", "orrv"):
                p = [x.strip() for x in ops.split(",")]
                a = self.regval(p[1]) if len(p) >= 2 else 0
                b = self.regval(p[2]) if len(p) >= 3 else 0
                if m == "add": v = (a + b) & 0xFFFFFFFF if a < 2**32 else a + b
                elif m == "sub": v = (a - b) & 0xFFFFFFFF if a < 2**32 else a - b
                elif m == "eor": v = a ^ b
                elif m == "and": v = a & b
                elif m == "orr": v = a | b
                elif m == "mul": v = (a * b) & 0xFFFFFFFF
                elif m == "lsl": v = (a << b) & 0xFFFFFFFF
                elif m == "lsr": v = (a >> b) & 0xFFFFFFFF
                self.R[p[0]] = v & 0xFFFFFFFFFFFFFFFF
            elif m in ("cmp", "cmn", "subs"):
                p = [x.strip() for x in ops.split(",")]
                a = self.regval(p[0]); b = self.regval(p[1]) if len(p) > 1 else 0
                if m == "cmn": d = a + b
                else: d = a - b
                self.F = {"eq": d == 0, "ne": d != 0, "lt": d < 0, "ge": d >= 0,
                          "gt": d > 0, "le": d <= 0,
                          "hs": (a - b) >= 0, "lo": (a - b) < 0,
                          "hi": (a - b) > 0, "ls": (a - b) <= 0}
            elif m == "b":
                t = pt(ops)
                if t is None: return "bad-b"
                if t == 0x100318: return "exit-clean"      # epilogue
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
                v = self.regval(p[0])
                t = pt(p[-1])
                if v == 0 and t is not None:
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "cbnz":
                p = [x.strip() for x in ops.split(",")]
                v = self.regval(p[0])
                t = pt(p[-1])
                if v != 0 and t is not None:
                    if t == 0x100318: return "exit-clean"
                    npc = t
            elif m == "ret":
                return "ret"
            elif m in ("ldr", "ldur", "ldp", "str", "stp", "stpq", "stur"):
                # memory ops on stack frame/queue — model the field loop's loads
                # field loop reads descriptor {w0, ptr} from [x27] / array [x20+idx*8]
                self.mem_op(i)
            elif m == "lsr":
                pass
            # register moves to/from special regs used by loops
            self.pc = npc
        return "steps-exhausted"

    def regval(self, s):
        s = s.strip()
        if s in ("wzr", "xzr"): return 0
        if s.startswith("#"): return pt(s) or 0
        v = self.R.get(s)
        if v is not None: return v
        # xN read as wN (low 32)
        if s.startswith("w") and ("x" + s[1:]) in self.R: return self.R["x" + s[1:]] & 0xFFFFFFFF
        if s.startswith("x") and ("w" + s[1:]) in self.R: return self.R["w" + s[1:]]
        try: return int(s, 0)
        except ValueError: return 0

    def mem_op(self, i):
        """model just enough loads: field-descriptor loop uses:
        ldr x27, [x8]            ; descriptor array elem
        ldr w8, [x27]            ; (len<<2)|tag
        ldr x1, [x28]            ; sink
        ldr x8, [x9, w22, lsl 2] ; stream data (from EMIT internals — not here)
        we track [x20+idx*8] as the fields array."""
        ops = i.op_str
        # ldr w8, [x27] -> descriptor word for current field
        if ops.startswith("w8, [x27]"):
            lendl, tag, data = self.fields[self.f_i] if self.f_i < len(self.fields) else (0, 0, b"")
            self.R["w8"] = (lendl << 2) | tag
        # ldr x1, [x28] or [x21]/[x23] -> sink pointer: opaque
        # ldr x0, [x8] inside field-loop: returns element pointer — opaque
        pass

def main():
    data = open("../device/adj9_hp3.log", encoding="utf-8", errors="replace").read()
    evs = re.findall(r"###ADJ9_BEGIN type=(nsign_in|nsign) utf8len=\d+ ts=(\d+)\ntext: (.*?)\nhex: ", data, re.S)
    pairs, pend = [], None
    for t, ts, txt in evs:
        if t == "nsign_in":
            mh = re.search(r"arg3_hex=([0-9a-f]{64})", txt)
            if mh: pend = (int(ts), mh.group(1))
        elif t == "nsign" and pend:
            mb = re.search(r"hex=([0-9a-f]{384})", txt)
            if mb: pairs.append((pend[0], pend[1], mb.group(1))); pend = None
    ts_in, H, blob = pairs[0]
    Hb = bytes.fromhex(H)
    z = b"\0" * 64
    fields = [(36,0,z*2),(0,0,b""),(1,0,z),(1,0,z),(8,0,Hb),(1,0,z),(1,0,z),(1,0,z),(4,0,z),(5,0,z),(4,0,z)]
    ex = Exec(fields, ts_in // 1000 + 1)
    # preload field-loop register state (from the 0x100114 head)
    ex.R["x20"] = 0xAAAA0000     # queue/farray base (opaque)
    ex.R["x19"] = 0xBBBB0000     # writer
    ex.R["x22"] = 0              # inner dword idx
    ex.R["x23"] = 0              # field idx
    ex.R["x26"] = len(fields)    # count
    status = ex.run()
    print("status:", status, " steps:", ex.steps, " nrand:", ex.nrand)
    print("dwords:", len(ex.s_data), " sections:", ex.s_off[:8])
    print("unknown ops:", sorted(hex(x) for x in ex.R.get("_unknown", set())))
    out = b"".join(struct.pack(">I", x) for x in ex.s_data)
    real = bytes.fromhex(blob)
    print("mine[:24]:", out[:24].hex())
    print("real[:24]:", real[:24].hex())
    print("EMIT log (first 16):", ex.emit_log[:16])

if __name__ == "__main__":
    main()
