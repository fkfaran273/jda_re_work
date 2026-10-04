#!/usr/bin/env python
"""Call-graph BFS from nSign using real `bl` targets only.

nSign is O-LLVM flattened, so its body is one huge function; sub-work is still
reached with real `bl`s, so a bl-only BFS is meaningful (unlike a CFG crawl,
which reaches essentially all of .text).
"""
import io, os
from collections import deque
from elftools.elf.elffile import ELFFile
import capstone

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
HERE = os.path.dirname(os.path.abspath(__file__))
data = open(SO, "rb").read()
elf = ELFFile(io.BytesIO(data))
text = {s.name: s for s in elf.iter_sections()} [".text"]
TX_OFF, TX_VA, TX_SZ = text["sh_offset"], text["sh_addr"], text["sh_size"]

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
code = data[TX_OFF:TX_OFF + TX_SZ]

# map: function start -> set of bl targets, plus instruction span
callees = {}
starts = set()
insns = list(md.disasm(code, TX_VA))
for ins in insns:
    if ins.mnemonic == "bl" and ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_IMM:
        starts.add(ins.operands[0].imm)
starts.add(TX_VA)
starts.add(0xDB1CC)          # nSign: force it to be its own function start
starts.add(0xDB1CC + 3188)   # and end the previous one right after it
sl = sorted(starts)
import bisect


def owner(va):
    i = bisect.bisect_right(sl, va) - 1
    return sl[i] if i >= 0 else TX_VA


for ins in insns:
    if ins.mnemonic == "bl" and ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_IMM:
        callees.setdefault(owner(ins.address), set()).add(ins.operands[0].imm)

NSIGN = 0xDB1CC
TARGETS = {0x12E5F4: "SHA1 ctx init", 0xE57C: "caller of SHA1 init",
           0x8D400: "loads .rodata+0xd0 (not constants)", 0x31924: "loads .rodata+0xf0 (not constants)"}

seen = {NSIGN}
parent = {NSIGN: None}
q = deque([NSIGN])
while q:
    f = q.popleft()
    for c in callees.get(f, ()):
        if c not in seen:
            seen.add(c)
            parent[c] = f
            q.append(c)

out = io.open(os.path.join(HERE, "reach_nsign.txt"), "w", encoding="utf8")
out.write("functions reachable from nSign by bl-BFS: %d\n\n" % len(seen))
for t, what in sorted(TARGETS.items()):
    out.write("0x%x  %-38s reachable: %s\n" % (t, what, t in seen))
    if t in seen:
        chain, x = [], t
        while x is not None and len(chain) < 40:
            chain.append("0x%x" % x)
            x = parent[x]
        out.write("      chain: %s\n" % " <- ".join(chain))
out.write("\n--- all reachable functions (sorted) ---\n")
for f in sorted(seen):
    out.write("0x%x\n" % f)
out.close()
print("wrote reach_nsign.txt  reachable=%d" % len(seen))
for t, what in sorted(TARGETS.items()):
    print("  0x%x %-38s reachable=%s" % (t, what, t in seen))
