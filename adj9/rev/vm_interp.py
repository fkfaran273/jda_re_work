"""vm_interp.py — concrete interpreter of the adj9 serializer program.
Walks 0x100094..0x12aa44 linearly (it is straight-line code: op-calls with
cbnz error guards), maintaining:
  - the value stack (queue q at [x20]: push 0x147630 / pop 0x147734)
  - the output stream object at [x19] (writer): EMIT 0x146ed8, LENQ 0x147304
  - bionic Random3 stream (for rand @ PLT 0x148d10)
Register convention recovered from disassembly:
  w0  = result of last POP / rand / LENQ
  w21 = result of the POP before that
  w2  = the argument built for the next PUSH/EMIT
  x26 / x20-family = context pointers (iterator source)
Semantics:
  PUSH q, v: prepend node {v, next}         (0x147630)
  POP q -> w0: take head value, free         (0x147734)
  EMIT(w, q, n, v): stream[offs_last + n] = v, grow   (0x146ed8)
  LENQ(q, n) -> w0: read stream[offs_last + n]        (0x147304)
  OUTLEN(w) -> w0: count - offs_last                  (0x1472e8)
  RAND -> w0: next Random3 draw                       (PLT)
Field inputs (11 descriptors) are supplied by the caller; the FIRST loop
(0x100114..0x100228) emits their raw bytes BE into the stream.
Unknown ops are logged for manual resolution."""
import sys, struct
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
from header_gen import Random3

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
LO, HI = 0x100094, 0x12aa44
insns = list(md.disasm(elf[LO:HI], LO))

PUSH, POP, EMIT, LENQ, OUTLEN = 0x147630, 0x147734, 0x146ed8, 0x147304, 0x1472e8
RAND_PLT, CAP, MKITER, ITERNEXT = 0x148d10, 0x14784c, 0x146558, 0x146650

def parse_t(s):
    try: return int(s.lstrip("#"), 16)
    except (ValueError, AttributeError): return None

class Stream:
    """the writer object: {cap, data*, count, offs_len, offs*}"""
    def __init__(self):
        self.data = []          # u32 list
        self.offs = [0]         # section start offsets
    def base(self):             # offs_last
        return self.offs[-1]
    def emit(self, n, v):
        pos = self.base() + n
        while len(self.data) <= pos:
            self.data.append(0)
        self.data[pos] = v & 0xFFFFFFFF
    def get(self, n):
        pos = self.base() + n
        return self.data[pos] if pos < len(self.data) else 0
    def newsec(self):
        self.offs.append(len(self.data))

class VM:
    def __init__(self, fields, rnd):
        self.stack = []          # value stack (queue semantics: prepend/pop)
        self.s = Stream()
        self.w0 = 0              # last result
        self.w21 = 0             # result before that
        self.fields = fields     # list of (len_dw, tag, bytes)
        self.fidx = 0
        self.iter_cnt = 0
        self.rnd = rnd
        self.trace = []
        self.unknown = []

def run(fields, seed, trace_limit=260):
    vm = VM(fields, Random3(seed))
    st = vm
    w2_imm = None               # immediate being built for w2
    pending_arith = None
    k = 0
    n = len(insns)
    while k < n:
        i = insns[k]
        m, ops = i.mnemonic, i.op_str
        # ---- track w2 immediate build & w21 saves ----
        if m == "mov" and ops.startswith("w2, #"):
            w2_imm = parse_t(ops.split("#")[1])
        elif m == "mov" and ops.startswith("w2, wzr"):
            w2_imm = 0
        elif m == "mov" and ops.startswith("w21, w0"):
            st.w21 = st.w0
        elif m in ("add", "sub", "eor", "and", "orr") and ops.startswith("w2,"):
            # w2 = w0 OP w21 / const   (arith over the two pops)
            parts = [p.strip() for p in ops.split(",")]
            a = st.w0
            b = st.w21 if parts[2] in ("w21", "w0") else parse_t(parts[2]) or 0
            if parts[1] == "w0":
                b = st.w21 if parts[2] == "w21" else (parse_t(parts[2]) or 0)
                if m == "add": st.w0 = a + b
                elif m == "sub": st.w0 = a - b
                elif m == "eor": st.w0 = a ^ b
                elif m == "and": st.w0 = a & b
                elif m == "orr": st.w0 = a | b
                # result stays in w0; caller PUSHes it
            else:
                pass
        # ---- ops ----
        elif m == "bl":
            t = parse_t(ops)
            if t == PUSH:
                v = st.w0 if w2_imm is None else (st.w0 if w2_imm == -1 else w2_imm)
                # PUSH's w2 arg: if it was 'mov w2, wzr' -> 0; constants -> imm.
                # BUT for value-pushes the pattern is: w2 = w0 (mov w2, w0)
                v = st.w0 if w2_imm is None else w2_imm
                st.stack.insert(0, v)
                st.trace.append(("PUSH", v))
            elif t == POP:
                v = st.stack.pop(0) if st.stack else 0
                st.w21, st.w0 = st.w0, v
                st.trace.append(("POP", v))
            elif t == EMIT:
                # w2 = n (offset), w3 = v — w3 usually w0-derived; track:
                st.s.emit(w2_imm if w2_imm is not None else 0, st.w0)
                st.trace.append(("EMIT", w2_imm, st.w0))
            elif t == LENQ:
                st.w0 = st.s.get(w2_imm or 0)
                st.trace.append(("LENQ", w2_imm or 0, st.w0))
            elif t == OUTLEN:
                st.w0 = len(st.s.data) - st.s.base()
                st.trace.append(("OUTLEN", st.w0))
            elif t == RAND_PLT:
                st.w0 = st.rnd.next()
                st.trace.append(("RAND", st.w0))
            elif t in (CAP, MKITER, ITERNEXT, 0x147a20, 0x147a18, 0x147120, 0x147220, 0x146474, 0x146478, 0x146470):
                st.unknown.append((hex(t), i.address))
            w2_imm = None
        elif m == "mov" and ops == "w2, w0":
            w2_imm = -1           # marker: w2 = w0
        elif m == "mov" and ops.startswith("w3, w0"):
            pass
        k += 1
    return st

if __name__ == "__main__":
    # fields: 11 descriptors (len_dw, tag, data placeholder)
    # real data comes from a logged nSign — placeholder ZEROS for structure test
    fields = [(36, 0), (0, 0), (1, 0), (1, 0), (8, 0), (1, 0), (1, 0), (1, 0), (4, 0), (5, 0), (4, 0)]
    st = run(fields, seed=1789072139)
    print("stream dwords:", len(st.s.data))
    print("sections:", st.s.offs)
    print("first 20 dwords: %s" % " ".join("%08x" % x for x in st.s.data[:20]))
    print("stack residue:", st.stack[:8])
    from collections import Counter
    print("trace op counts:", Counter(t[0] for t in st.trace).most_common())
    print("unknown ops:", Counter(u[0] for u in st.unknown).most_common())
