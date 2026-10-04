"""Disassembly/analysis helper for libsigner.so d0 materializer at 0x1437ec.

Usage:
  python adj9_d0_analysis.py func      # extent + disasm of 0x1437ec
  python adj9_d0_analysis.py callers    # all BL to 0x1437ec
  python adj9_d0_analysis.py tails      # all BL to 0x1441e4
  python adj9_d0_analysis.py ctx        # disasm around each caller
  python adj9_d0_analysis.py raw <hex>  # raw bytes at addr
  python adj9_d0_analysis.py trace      # Unicorn trace: executed tail-calls per seed
  python adj9_d0_analysis.py globals    # PLT/GOT/TLS touch analysis
"""
import struct, sys
from capstone import *
from unicorn import *
from unicorn.arm64_const import *

SO = "extracted/arm64/lib/arm64-v8a/libsigner.so"
d = open(SO, "rb").read()

MAP_BASE = 0x0
MAP_SIZE = 0x160000
STACK    = 0x70000000
TLS      = 0x71000000
CTX      = 0x72000000
LR_SENT  = 0x73000000

ENTRY = 0x1437ec
TAIL  = 0x1441e4
SEL   = 0x143b20
WHIT  = 0x144074

def disasm(addr, count=40, bytes_wanted=True):
    off = addr
    blob = d[off:off+count*4]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for i in md.disasm(blob, addr):
        raw = d[i.address:i.address+i.size].hex()
        print("%08x  %-10s %-40s %s" % (i.address, raw, i.mnemonic, i.op_str))
        count -= 1
        if count == 0:
            break

def raw(addr, n=32):
    print("bytes @%#x:" % addr, d[addr:addr+n].hex())

def func_extent():
    # scan forward from 0x1437ec for the epilogue: ret / br xN return
    print("=== function extent of 0x1437ec (scan for ret/epilogue) ===")
    # find the first 'ret' (d65f03c0) and print its context
    target = bytes.fromhex("d65f03c0")  # ret
    for addr in range(ENTRY, 0x160000, 4):
        if d[addr:addr+4] == target:
            print("ret @ %#x" % addr)
            # show context: is it a function epilogue? look backwards for stack restore
            disasm(max(ENTRY, addr-64), 18)
            # continue: after this ret, find next ret (phase 2?)
            break
    # also dump a few hundred instructions after entry looking for 'br x?'
    print("\n--- first 120 insns of 0x1437ec ---")
    disasm(ENTRY, 120)

def all_callers(target):
    print("=== all BL to %#x ===" % target)
    # AArch64 BL encoding: 1001 01ii iiii iiii iiii iiii iiiiii 00000
    # imm26 = sign_extend(imm26)<<2; addr = pc + off
    hits = []
    for addr in range(MAP_BASE, 0x148e60, 4):
        w = struct.unpack_from("<I", d, addr)[0]
        if (w & 0xfc000000) == 0x94000000:
            imm = w & 0x03ffffff
            if imm & 0x02000000:
                imm -= 0x04000000
            dest = addr + (imm << 2)
            if dest == target:
                hits.append(addr)
    for a in hits:
        print("\nBL %s <- %#x" % (hex(target), a))
        disasm(max(0, a-48), 14)
    return hits

def trace(seed, max_insn=50_000_000, collect_tails=True):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu.mem_map(MAP_BASE, MAP_SIZE, UC_PROT_ALL)
    mu.mem_write(MAP_BASE, d[:MAP_SIZE])
    mu.mem_map(STACK, 0x20000)
    mu.mem_map(TLS, 0x2000)
    mu.mem_write(TLS + 0x28, struct.pack("<Q", 0x1122334455667788))
    mu.mem_map(CTX, 0x4000)
    mu.mem_write(TLS + 0x0, b"\x00"*0x28)  # zero rest of TLS
    mu.mem_write(CTX, b"\x00" * 0x4000)
    mu.mem_map(LR_SENT, 0x10000)
    mu.reg_write(UC_ARM64_REG_LR, LR_SENT)
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x18000)
    mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    mu.reg_write(UC_ARM64_REG_X0, CTX)
    mu.reg_write(UC_ARM64_REG_W1, seed & 0xffffffff)

    state = {"stop": None, "count": 0}
    tail_hits = []      # (caller_addr, seed_when_called) for BL TAIL
    tail_exec = []      # (addr) in execution order
    call_sites = []     # every BL executed whose target in known set
    known = {TAIL, ENTRY, SEL, WHIT}

    def code(uc, addr, size, ud):
        state["count"] += 1
        if addr == LR_SENT:
            state["stop"] = "returned"
            uc.emu_stop()
            return
        if addr in known:
            tail_exec.append((addr, state["count"]))

    def invalid(uc, access, addr, size, value, ud):
        state["stop"] = "mem_invalid access=%d addr=%#x size=%d" % (access, addr, size)
        uc.emu_stop()
        return False

    mu.hook_add(UC_HOOK_CODE, code)
    mu.hook_add(UC_HOOK_MEM_INVALID, invalid)

    # Static scan: which BL sites target TAIL
    tail_sites = set()
    for addr in range(MAP_BASE, 0x148e60, 4):
        w = struct.unpack_from("<I", d, addr)[0]
        if (w & 0xfc000000) == 0x94000000:
            imm = w & 0x03ffffff
            if imm & 0x02000000:
                imm -= 0x04000000
            if addr + (imm << 2) == TAIL:
                tail_sites.add(addr)
    for a in sorted(tail_sites):
        tail_hits.append((a, 0))

    try:
        mu.emu_start(ENTRY, LR_SENT, count=max_insn)
    except UcError as e:
        state["stop"] = state["stop"] or ("ucerror %s" % e)
    return mu, state, tail_exec, tail_sites

def globals_analysis():
    # Scan entry + reachable near functions for ADRP/ADD pairs producing
    # addresses in data/rodata, and MRS reads (TLS), and any BL to PLT stubs.
    print("=== MRS/ADRP/PLT analysis around entry & callees ===")
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    # find PLT range: typical .plt near start; look for stub pattern
    # We know rodata starts ~0x14ce60. Find ADRP targets in that window
    def scan(addr0, addr1, label):
        for a in range(addr0, addr1, 4):
            w = struct.unpack_from("<I", d, a)[0]
            # MRS Xn, tpidr_el0
            if (w & 0xffe00000) == 0xd53bd040:
                print("%s: MRS TPIDR_EL0 @%#x" % (label, a))
            # ADRP
            if (w & 0x9f000000) == 0x90000000:
                immlo = (w >> 29) & 3
                immhi = (w >> 5) & 0x7ffff
                imm = (immhi << 2) | immlo
                if imm & 0x100000: imm -= 0x200000
                page = (a & ~0xfff) + (imm << 12)
                if page >= 0x14ce60:
                    print("%s: ADRP -> %#x (data/rodata) @%#x" % (label, a, page))
    scan(ENTRY, 0x1441e4, "entry..tail")
    scan(0x144214, 0x148e60, "after-tail")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "func"
    if cmd == "func":
        func_extent()
    elif cmd == "callers":
        all_callers(ENTRY)
    elif cmd == "tails":
        all_callers(TAIL)
    elif cmd == "trace":
        for seed in (0x11223344, 0xdeadbeef, 0, 1, 0xffffffff, 0x12345678, 0xabcdef01):
            mu, st, te, sites = trace(seed)
            tails_done = [hex(a) for a, c in te if a == TAIL]
            print("seed %#x: stop=%s insns=%d tail-exec=%d" % (seed, st["stop"], st["count"], len(tails_done)))
            print("   tail exec order:", tails_done)
    elif cmd == "globals":
        globals_analysis()
    elif cmd == "raw":
        raw(int(sys.argv[2], 16), int(sys.argv[3]) if len(sys.argv) > 3 else 32)
    else:
        print("unknown cmd")
