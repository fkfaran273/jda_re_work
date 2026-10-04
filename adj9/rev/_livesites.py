# resolve what each live bl-site calls: disassemble window, get bl target,
# identify containing function of the bl site, and recursively name callees
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Apps\Downloads\com.penti.app\split_config.arm64_v8a.apk"
OFF = 0x54000
SZ = 0x149000

f = open(SO, 'rb')
f.seek(OFF)
data = f.read(SZ)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

def insns_at(va, n=40, back=0):
    start = va - back * 4
    if start < 0: start = 0
    code = data[start:start + (n + back) * 4]
    out = []
    for i in md.disasm(code, start):
        out.append(i)
    return out

def bl_target(va):
    """disassemble the single instruction at va (must be bl) -> target"""
    for i in md.disasm(data[va:va + 4], va):
        if i.mnemonic in ('bl', 'b'):
            return int(i.op_str.replace('#', ''), 16)
    return None

# function-start heuristic: scan backwards for 'stp x29, x30' prologue or 'pacisp'
def func_start(va, maxback=0x3000):
    a = max(0, va - maxback)
    code = data[a:va + 4]
    best = None
    for i in md.disasm(code, a):
        if i.mnemonic == 'stp' and i.op_str.startswith('x29, x30'):
            best = i.address
        elif i.mnemonic == 'pacibsp':
            best = i.address
    return best

sites = [0x09afe8, 0x0e2900, 0x0e2608, 0x0e2b70, 0x0299f0, 0x039aa0, 0x01c8b4,
         0x01c5f4, 0x13dec0, 0x0db898, 0x021a18, 0x0e5604, 0x0e587c, 0x0e94a8,
         0x09c6a4, 0x0bb9c8, 0x016fb4, 0x014ff8, 0x0daf94, 0x0bef80, 0x0daf8c,
         0x0204b4, 0x00debc, 0x0da8ec, 0x022a94, 0x134104, 0x00e780, 0x0da8f4, 0x020d8c]

print("%-10s %-12s %-10s" % ("bl site", "callee", "caller fn"))
for s in sites:
    t = bl_target(s)
    fs = func_start(s)
    tstr = ("0x%06x" % t) if t else "?"
    fstr = ("0x%06x" % fs) if fs else "?"
    print("0x%06x   %-12s %s" % (s, tstr, fstr))
