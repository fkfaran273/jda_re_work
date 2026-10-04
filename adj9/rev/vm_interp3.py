"""vm_interp3.py — interpreter with the empirically-derived register contract.

Contract (from context tabulation of all 4,500 call sites):
  POP   -> w0 = value popped; w21 = previous w0 (chained by the fn's code:
           after each op the site does NOT re-move w0->w21; the POP op
           itself sets w21 = old w0 via 'mov w21, w0' INSIDE the program —
           verified: LENQ sites show 'mov w1, w0' then next op)
  PUSH  arg: 'mov w2, w0' | 'add w2, w0, w21' | 'add w2, w0, #1' | 'eor w2, w0, w21' | imm
  EMIT  arg: n = w21/w22/w25 (register), v = w3 = w0 of LENQ just before
  LENQ  arg: w1 = w0 or arith; result -> w0
  RAND  -> w0; then 'mov w2, w0'; PUSH  (the header loop)
  The interpreter therefore tracks w0/w21/w22/w23/w25/w27 as a small
  register file and executes the site patterns directly.
"""
import sys, struct, json, re
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
from header_gen import Random3

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True

PUSH, POP, EMIT, LENQ, OUTLEN = 0x147630, 0x147734, 0x146ed8, 0x147304, 0x1472e8
PUSHS, POPS, RAND_PLT = 0x147120, 0x147220, 0x148d10
IGNORED = {0x14784c, 0x147a20, 0x147a18, 0x146558, 0x146650, 0x146470, 0x146474, 0x146478}

def parse_t(s):
    try: return int(s.lstrip("#"), 16)
    except (ValueError, AttributeError): return None

class Stream:
    def __init__(self):
        self.data = []
        self.offstack = [0]
    def base(self): return self.offstack[-1]
    def emit(self, n, v):
        pos = self.base() + n
        if pos < 0 or pos > 4096: return
        while len(self.data) <= pos: self.data.append(0)
        self.data[pos] = v & 0xFFFFFFFF
    def get(self, n):
        pos = self.base() + n
        return self.data[pos] if 0 <= pos < len(self.data) else 0

def run(fields, seed):
    rnd = Random3(seed)
    stack = []
    s = Stream()
    R = {n: 0 for n in ("w0","w1","w2","w3","w21","w22","w23","w25","w27")}
    nrand = 0
    sec_events = []
    # ---- field loop ----
    pos = 0
    for (lendl, tag, data) in fields:
        for j in range(lendl):
            s.emit(pos, struct.unpack_from(">I", data, 4*j)[0] if len(data) >= 4*(j+1) else 0)
            pos += 1
    # ---- queue program ----
    insns = list(md.disasm(elf[0x100228:0x12aa44], 0x100228))
    for i in insns:
        m, ops = i.mnemonic, i.op_str
        if m == "mov":
            d, srt = [p.strip() for p in ops.split(",", 1)]
            if d in R:
                R[d] = R[srt] if srt in R else (parse_t(srt) if srt.startswith(("#", "0x")) or srt.lstrip("#").lstrip("0x").isdigit() else 0)
                if srt == "wzr": R[d] = 0
        elif m in ("add", "sub", "eor", "and", "orr"):
            p = [x.strip() for x in ops.split(",")]
            if p[0] in R:
                a = R.get(p[1], parse_t(p[1]) or 0) if p[1] in R else (parse_t(p[1]) if p[1].startswith("#") else 0)
                b = R.get(p[2], 0) if p[2] in R else (parse_t(p[2]) if p[2].startswith("#") else 0)
                if m == "add": R[p[0]] = (a + b) & 0xFFFFFFFF
                elif m == "sub": R[p[0]] = (a - b) & 0xFFFFFFFF
                elif m == "eor": R[p[0]] = a ^ b
                elif m == "and": R[p[0]] = a & b
                elif m == "orr": R[p[0]] = a | b
        elif m == "bl":
            t = parse_t(ops)
            if t == PUSH:
                stack.insert(0, R["w2"])
            elif t == POP:
                R["w21"] = R["w0"]
                R["w0"] = stack.pop(0) if stack else 0
            elif t == EMIT:
                s.emit(R["w2"], R["w3"])
            elif t == LENQ:
                R["w21"] = R["w0"] if False else R["w0"]  # LENQ reads w1 = arg
                R["w0"] = s.get(R["w1"])
            elif t == OUTLEN:
                R["w21"] = R["w0"]
                R["w0"] = len(s.data) - s.base()
            elif t == PUSHS:
                sec_events.append(("PUSHS", len(s.data)))
                s.offstack.append(R["w1"] if R["w1"] else len(s.data))
            elif t == POPS:
                sec_events.append(("POPS", len(s.data)))
                if len(s.offstack) > 1: s.offstack.pop()
            elif t == RAND_PLT:
                R["w21"] = R["w0"]
                R["w0"] = rnd.next() & 0xFFFFFFFF
                nrand += 1
            # ignored: iterator machinery
    return s, stack, nrand, sec_events

if __name__ == "__main__":
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
    for Toff in (1, 0, 2):
        s, stack, nrand, secs = run(fields, ts_in // 1000 + Toff)
        print("T+%d: dwords=%d nrand=%d stack=%d secs=%s" % (Toff, len(s.data), nrand, len(stack), secs[:6]))
        out = b"".join(struct.pack(">I", x) for x in s.data)
        real = bytes.fromhex(blob)
        print("   hdr mine:", out[:16].hex())
        print("   hdr real:", real[:16].hex())
        m = sum(1 for a, b in zip(out[:192], real) if a == b)
        print("   matching bytes: %d/192" % m)
        if m >= 16: break
