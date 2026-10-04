import struct
from unicorn import *
from unicorn.arm64_const import *

SO = "extracted/arm64/lib/arm64-v8a/libsigner.so"
d = open(SO, "rb").read()

# Address layout (vaddr == file offset in the text segment)
MAP_BASE = 0x0
MAP_SIZE = 0x160000         # covers text+rodata+data+bss (bss zero via memmap)
STACK    = 0x70000000
TLS      = 0x71000000
CTX      = 0x72000000
LR_SENT  = 0x73000000       # fake return address we watch for

ENTRY = 0x1437ec

def run(seed, max_insn=50_000_000):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    # map whole image, copy file (bss beyond EOF stays zero)
    mu.mem_map(MAP_BASE, MAP_SIZE, UC_PROT_ALL)
    mu.mem_write(MAP_BASE, d[:MAP_SIZE])
    # stack
    mu.mem_map(STACK, 0x20000)
    # tls
    mu.mem_map(TLS, 0x2000)
    mu.mem_write(TLS + 0x28, struct.pack("<Q", 0x1122334455667788))
    # ctx
    mu.mem_map(CTX, 0x4000)
    mu.mem_write(CTX, b"\x00" * 0x4000)
    # LR sentinel page
    mu.mem_map(LR_SENT, 0x1000)

    mu.reg_write(UC_ARM64_REG_LR, LR_SENT)
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x18000)
    mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    mu.reg_write(UC_ARM64_REG_X0, CTX)
    mu.reg_write(UC_ARM64_REG_W1, seed & 0xffffffff)

    state = {"stop": None, "count": 0}

    def code(uc, addr, size, ud):
        state["count"] += 1
        if addr == LR_SENT:
            state["stop"] = "returned"
            uc.emu_stop()

    def invalid(uc, access, addr, size, value, ud):
        state["stop"] = "mem_invalid access=%d addr=%#x size=%d" % (access, addr, size)
        uc.emu_stop()
        return False

    mu.hook_add(UC_HOOK_CODE, code)
    mu.hook_add(UC_HOOK_MEM_INVALID, invalid)

    try:
        mu.emu_start(ENTRY, LR_SENT, count=max_insn)
    except UcError as e:
        state["stop"] = state["stop"] or ("ucerror %s" % e)
    ctx = mu.mem_read(CTX, 0x4000)
    return ctx, state

if __name__ == "__main__":
    for seed in (0x11223344, 0xdeadbeef):
        ctx, st = run(seed)
        print("seed %#x -> %s insns=%d" % (seed, st["stop"], st["count"]))
