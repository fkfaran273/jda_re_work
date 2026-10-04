"""vm_interp2.py — full concrete interpreter of the adj9 serializer.

Program layout (all verified clean code):
  0x100114..0x100228  field loop: for each of the 11 descriptors,
                      emit the field's raw dwords BE into the stream
  0x100228..0x100318 straight-line queue program (the serializer core)
  ops: PUSH/POP stack; EMIT(stream, n, v) at offs_last+n; LENQ(n) reads
       stream[offs_last+n]; OUTLEN; PUSHS 0x147120 (push section start);
       POPS 0x147220 (pop section start); RAND.
Register contract per disassembly:
  w0 = latest op result; w21 = previous; w2 = arg (imm / w0 / arith);
  w3 = EMIT value; w15/w16 = section-start scratch.
"""
import sys, struct, json, re
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
from header_gen import Random3

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True

PUSH, POP, EMIT, LENQ, OUTLEN = 0x147630, 0x147734, 0x146ed8, 0x147304, 0x1472e8
PUSHS, POPS = 0x147120, 0x147220
RAND_PLT = 0x148d10
IT_OPS = {0x14784c, 0x147a20, 0x147a18, 0x146558, 0x146650, 0x146470, 0x146474, 0x146478}

def parse_t(s):
    try: return int(s.lstrip("#"), 16)
    except (ValueError, AttributeError): return None

def disas_range(lo, hi):
    return list(md.disasm(elf[lo:hi], lo))

class Stream:
    def __init__(self):
        self.data = []
        self.offstack = [0]
        self.seclog = []
    def base(self): return self.offstack[-1]
    def emit(self, n, v):
        pos = self.base() + n
        while len(self.data) <= pos: self.data.append(0)
        self.data[pos] = v & 0xFFFFFFFF
    def get(self, n):
        pos = self.base() + n
        return self.data[pos] if pos < len(self.data) else 0
    def pushs(self, scratch):
        self.offstack.append(scratch)
        self.seclog.append(("PUSHS", scratch, len(self.data)))
    def pops(self):
        v = self.offstack.pop() if len(self.offstack) > 1 else 0
        self.seclog.append(("POPS", v, len(self.data)))
        return v

class VM:
    def __init__(self, fields, rnd):
        self.scratch = 0
        self.stack = []
        self.s = Stream()
        self.w0 = 0
        self.w21 = 0
        self.w2 = None          # None = unset; int = literal; "w0"/"w21" = source
        self.w3 = None
        self.fields = fields
        self.rnd = rnd
        self.nrand = 0
        self.iters = {}          # iterator state per unknown op
        self.it_ops_seen = {}
        self.sec = []

def run(fields, seed, dump=False):
    vm = VM(fields, Random3(seed))
    st = vm
    # ---- pass 1: the field loop (0x100114..0x100228) ----
    # for each descriptor {w0=(len_dw<<2)|tag, ptr}: emit its dwords BE at
    # sequential positions of the CURRENT section. Implemented directly:
    pos = 0
    for (lendl, tag, data) in fields:
        for j in range(lendl):
            st.s.emit(pos, struct.unpack_from(">I", data, 4*j)[0] if len(data) >= 4*(j+1) else 0)
            pos += 1
    # ---- pass 2: queue program 0x100228..0x12aa44 ----
    insns = disas_range(0x100228, 0x12aa44)
    idxmap = {i.address: k for k, i in enumerate(insns)}
    k = 0
    n = len(insns)
    while k < n:
        i = insns[k]
        m, ops = i.mnemonic, i.op_str
        if m == "mov":
            d, s = [p.strip() for p in ops.split(",", 1)]
            if d == "w2":
                if s == "wzr": st.w2 = 0
                elif s == "w0": st.w2 = "w0"
                elif s == "w21": st.w2 = "w21"
                elif s.startswith("#"): st.w2 = parse_t(s)
            elif d == "w3":
                if s == "w0": st.w3 = st.w0
                elif s == "w21": st.w3 = st.w21
                elif s.startswith("#"): st.w3 = parse_t(s)
            elif d == "w21" and s == "w0":
                st.w21 = st.w0
        elif m in ("add", "sub", "eor", "and", "orr"):
            parts = [p.strip() for p in ops.split(",")]
            if parts[0] == "w2" and len(parts) == 3:
                a = st.w0 if parts[1] == "w0" else (st.w21 if parts[1] == "w21" else parse_t(parts[1]))
                b = st.w0 if parts[2] == "w0" else (st.w21 if parts[2] == "w21" else parse_t(parts[2]))
                if a is not None and b is not None:
                    if m == "add": st.w2 = (a + b) & 0xFFFFFFFF
                    elif m == "sub": st.w2 = (a - b) & 0xFFFFFFFF
                    elif m == "eor": st.w2 = a ^ b
                    elif m == "and": st.w2 = a & b
                    elif m == "orr": st.w2 = a | b
        elif m == "bl":
            t = parse_t(ops)
            if t == PUSH:
                v = st.w0 if st.w2 in (None, "w0") else (st.w21 if st.w2 == "w21" else st.w2)
                st.stack.insert(0, v)
            elif t == POP:
                v = st.stack.pop(0) if st.stack else 0
                st.w0, st.w21 = v, st.w0
            elif t == EMIT:
                nn = st.w0 if st.w2 == "w0" else (st.w21 if st.w2 == "w21" else (st.w2 if isinstance(st.w2, int) else 0))
                vv = st.w3 if isinstance(st.w3, int) else st.w0
                nn = nn if isinstance(nn, int) and 0 <= nn < 256 else 0
                st.s.emit(nn, vv & 0xFFFFFFFF)
            elif t == LENQ:
                nn = st.w0 if st.w2 == "w0" else (st.w2 if isinstance(st.w2, int) else 0)
                st.w21 = st.w0
                st.w0 = st.s.get(nn)
            elif t == OUTLEN:
                st.w21 = st.w0
                st.w0 = len(st.s.data) - st.s.base()
            elif t == PUSHS:
                st.s.pushs(st.scratch)
            elif t == POPS:
                st.s.scratch = st.s.pops()
            elif t == RAND_PLT:
                st.w21 = st.w0
                st.w0 = st.rnd.next() & 0xFFFFFFFF
                st.nrand += 1
            elif t in IT_OPS:
                st.it_ops_seen[t] = st.it_ops_seen.get(t, 0) + 1
            st.w2 = None
            st.w3 = None
        k += 1
    return st

if __name__ == "__main__":
    import base64
    # one real nSign pair from adj9_hp3.log: H, blob, second
    data = open("../device/adj9_hp3.log", encoding="utf-8", errors="replace").read()
    evs = re.findall(r"###ADJ9_BEGIN type=(nsign_in|nsign) utf8len=\d+ ts=(\d+)\ntext: (.*?)\nhex: ", data, re.S)
    pairs = []
    pend = None
    for t, ts, txt in evs:
        if t == "nsign_in":
            mh = re.search(r"arg3_hex=([0-9a-f]{64})", txt)
            if mh: pend = (int(ts), mh.group(1))
        elif t == "nsign" and pend:
            mb = re.search(r"hex=([0-9a-f]{384})", txt)
            if mb:
                pairs.append((pend[0], pend[1], mb.group(1)))
                pend = None
    print("pairs:", len(pairs))
    # fields: 11 descriptors — lengths from statics; H = field 5
    ts_in, H, blob = pairs[0]
    T = ts_in // 1000 + 1
    Hb = bytes.fromhex(H)
    zeros = b"\0" * 64
    fields = [
        (36, 0, zeros * 2),                       # 144-B core record (unknown yet)
        (0, 0, b""),                              # zero/NULL
        (1, 0, zeros[:4]),
        (1, 0, zeros[:4]),                        # var-len placeholder
        (8, 0, Hb),                               # H (32 B)
        (1, 0, zeros[:4]),
        (1, 0, zeros[:4]),
        (1, 0, zeros[:4]),
        (4, 0, zeros[:16]),
        (5, 0, zeros[:20]),
        (4, 0, zeros[:16]),
    ]
    st = run(fields, seed=T)
    print("dwords:", len(st.s.data), " nrand:", st.nrand)
    print("sections:", st.s.seclog[:10])
    print("stack residue len:", len(st.stack))
    body = b"".join(struct.pack(">I", x) for x in st.s.data)[:44]
    real = bytes.fromhex(blob)[16:]
    print("stream[:12]:", body[:48].hex())
    print("body  [:12]:", real[:48].hex())
    print("it_ops_seen:", {hex(k): v for k, v in st.it_ops_seen.items()})
