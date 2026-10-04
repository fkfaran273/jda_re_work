"""emu_be168.py - emulate libsigner.so sub_be168 (0xbe168) under Unicorn with a fake
JNIEnv, tracing every JNI call (slot, args, decrypted string args) and the stores to
the out-pointer. Resolves PLT imports via .rela.plt.
Usage: python emu_be168.py <name_blob_va_hex> <out_ptr_choice 0|1>
"""
import struct
import sys
from unicorn import *
from unicorn.arm64_const import *

LIB = r"..\..\extracted\arm64\lib\arm64-v8a\libsigner.so"
elf = open(LIB, "rb").read()

# ---- parse sections & relocations ----
e_shoff = struct.unpack_from("<Q", elf, 0x28)[0]
e_shentsize = struct.unpack_from("<H", elf, 0x3A)[0]
e_shnum = struct.unpack_from("<H", elf, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", elf, 0x3E)[0]


def sh(i):
    o = e_shoff + i * e_shentsize
    return struct.unpack_from("<IIQQQQIIQQ", elf, o)


stro = sh(e_shstrndx)[4]
secs = {}
for i in range(e_shnum):
    s = sh(i)
    nm = elf[stro + s[0]:elf.index(b"\x00", stro + s[0])].decode()
    secs[nm] = s

dynsym = secs[".dynsym"]
dynstr = secs[".dynstr"]


def sym_name(idx):
    o = dynsym[4] + idx * 24
    st_name = struct.unpack_from("<I", elf, o)[0]
    e = elf.index(b"\x00", dynstr[4] + st_name)
    return elf[dynstr[4] + st_name:dynstr[4] + st_name + (e - dynstr[4] - st_name)].decode()


# .rela.plt entries: (offset, info, addend) - rtype 1026 = JUMP_SLOT
plt_syms = {}
ro = secs[".rela.plt"][4]
rn = secs[".rela.plt"][5] // 24
for i in range(rn):
    off, info, add = struct.unpack_from("<QQq", elf, ro + i * 24)
    plt_syms[off] = sym_name(info >> 32)

# PLT entry i (i>=1) is at plt_start + 16*i? (PLT0 = 32 bytes usually; entries 16B here)
plt_start = secs[".plt"][3]
plt_size = secs[".plt"][5]
# map got slot -> plt entry addr by decoding each entry's adrp/ldr
got_to_plt = {}
md = None
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
for ent in range(1, plt_size // 16):
    addr = plt_start + ent * 16
    code = elf[addr:addr + 16]
    got = None
    adrp_base = None
    for ins in md.disasm(code, addr):
        if ins.mnemonic == "adrp":
            adrp_base = ins.operands[1].imm
        elif ins.mnemonic == "ldr" and adrp_base is not None:
            got = adrp_base + ins.operands[-1].mem.disp
            break
    if got:
        got_to_plt[got] = addr

PLT_NAME = {}
for got, paddr in got_to_plt.items():
    if got in plt_syms:
        PLT_NAME[paddr] = plt_syms[got]

# ---- unicorn setup ----
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
STACK = 0x30000000000
FAKE = 0x40000000000
mu.mem_map(0x0, 0x160000)  # code + rodata + data, all below 0x160000
mu.mem_write(0x0, elf[:0x148e60])
mu.mem_write(0x14ce60, elf[0x148e60:0x148e60 + 0xdc0])
mu.mem_write(0x151c20, elf[0x149c20:0x149c20 + 0x360a])
mu.mem_map(STACK, 0x200000)
mu.mem_map(FAKE, 0x10000)
mu.mem_map(0x66600000, 0x1000)  # magic JNI trampoline page
mu.mem_write(0x66600000 & ~0xFFF, struct.pack("<I", 0xD65F03C0) * 1024)  # filler 'ret'

ENV = FAKE + 0x1000
FUNCS = FAKE + 0x2000
mu.mem_write(ENV, struct.pack("<Q", FUNCS))
OBJ = 0x51000000000  # fake jobject
mu.mem_map(OBJ & ~0xFFF, 0x1000)

JNI_NAMES = {0x78: "ExceptionCheck", 0xF8: "GetObjectClass", 0xB8: "DeleteLocalRef", 0x108: "GetMethodID",
             0x110: "CallObjectMethod", 0x2F0: "GetFieldID", 0x2F8: "GetObjectField",
             0x320: "GetIntField", 0x350: "CallStaticObjectMethod", 0x2E8: "GetStaticFieldID",
             0x2F8 + 8: "GetStaticObjectField"}


def rd_str(addr):
    out = b""
    for i in range(256):
        c = mu.mem_read(addr + i, 1)
        if c == b"\x00":
            break
        out += c
    return out.decode("latin1")


trace = []
MAGIC_BASE = 0x66600000


def cstr_args(x2, x3):
    s2 = s3 = None
    try:
        s2 = rd_str(x2)
    except Exception:
        pass
    try:
        s3 = rd_str(x3)
    except Exception:
        pass
    return s2, s3


def hook_code(mu, address, size, user_data):
    # stub the builder walk
    # JNI magic calls
    if MAGIC_BASE <= address < MAGIC_BASE + 0x1000:
        slot = address - MAGIC_BASE
        x1 = mu.reg_read(UC_ARM64_REG_X1)
        x2 = mu.reg_read(UC_ARM64_REG_X2)
        x3 = mu.reg_read(UC_ARM64_REG_X3)
        nm = JNI_NAMES.get(slot, "slot_0x%x" % slot)
        if nm == "GetObjectClass":
            trace.append("GetObjectClass(env, obj=0x%x)" % x1)
            mu.reg_write(UC_ARM64_REG_X0, FAKE + 0x30)
        elif nm == "GetFieldID":
            s2, s3 = cstr_args(x2, x3)
            trace.append("GetFieldID(env, clazz=0x%x, name=%r, sig=%r) [name@0x%x sig@0x%x]"
                         % (x1, s2, s3, x2, x3))
            mu.reg_write(UC_ARM64_REG_X0, FAKE + 0x40)
        elif nm == "GetIntField":
            trace.append("GetIntField(env, obj=0x%x, fid=0x%x) -> 0x2a (fake)" % (x1, x2))
            mu.reg_write(UC_ARM64_REG_X0, 0x2A)
        elif nm == "GetObjectField":
            trace.append("GetObjectField(env, obj=0x%x, fid=0x%x) -> fakestr" % (x1, x2))
            mu.reg_write(UC_ARM64_REG_X0, OBJ)
        elif nm == "GetMethodID":
            s2, s3 = cstr_args(x2, x3)
            trace.append("GetMethodID(env, clazz=0x%x, name=%r, sig=%r) [name@0x%x sig@0x%x]"
                         % (x1, s2, s3, x2, x3))
            mu.reg_write(UC_ARM64_REG_X0, FAKE + 0x50)
        elif nm == "CallObjectMethod":
            trace.append("CallObjectMethod(env, obj=0x%x, mid=0x%x) -> fakestr" % (x1, x2))
            mu.reg_write(UC_ARM64_REG_X0, OBJ)
        elif nm == "ExceptionCheck":
            trace.append("ExceptionCheck(env) -> 0")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif nm == "DeleteLocalRef":
            trace.append("DeleteLocalRef(env, 0x%x)" % x1)
            mu.reg_write(UC_ARM64_REG_X0, 0)
        else:
            trace.append("%s(env, 0x%x, 0x%x, 0x%x)" % (nm, x1, x2, x3))
            mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return
    # PLT stubs
    if plt_start <= address < plt_start + plt_size:
        nm = PLT_NAME.get(address, "plt_0x%x" % address)
        a0 = mu.reg_read(UC_ARM64_REG_X0)
        a1 = mu.reg_read(UC_ARM64_REG_X1)
        a2 = mu.reg_read(UC_ARM64_REG_X2)
        if nm in ("memcpy", "memmove"):
            mu.mem_write(a0, bytes(mu.mem_read(a1, a2)))
            mu.reg_write(UC_ARM64_REG_X0, a0)
        elif nm == "memset":
            mu.mem_write(a0, bytes([a2 & 0xFF]) * a1)
            mu.reg_write(UC_ARM64_REG_X0, a0)
        elif nm in ("malloc", "calloc"):
            mu.reg_write(UC_ARM64_REG_X0, FAKE + 0x8000)
        else:
            trace.append("PLT %s(0x%x, 0x%x, 0x%x) -> 0" % (nm, a0, a1, a2))
            mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return


# ---- apply R_AARCH64_RELATIVE relocations ----
def apply_relocs(uc, base_segs):
    d = secs[".rela.dyn"]
    off, size = d[4], d[5]
    n = 0
    for i in range(size // 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", elf, off + i * 24)
        if (r_info & 0xFFFFFFFF) == 0x403:  # R_AARCH64_RELATIVE
            for fva, fo, fsz in base_segs:
                if fva <= r_off < fva + fsz:
                    uc.mem_write(r_off, struct.pack("<Q", r_add & 0xFFFFFFFFFFFFFFFF))
                    n += 1
                    break
    return n

RELOC_COUNT = apply_relocs(mu, [(0x0, 0x0, 0x160000)])
print("# relocations applied:", RELOC_COUNT)

mu.hook_add(UC_HOOK_CODE, hook_code)

# fill the JNI function table with magic pointers
for slot in list(JNI_NAMES) + [0x30, 0x38, 0x40, 0x48, 0x50, 0x58]:
    mu.mem_write(FUNCS + slot, struct.pack("<Q", MAGIC_BASE + slot))


def rd_str2(uc, addr):
    out = b""
    for i in range(256):
        c = uc.mem_read(addr + i, 1)
        if c == b"\x00":
            break
        out += c
    return out.decode("latin1")

# ==== mode: emulate sub_8d6f4 (region builder) end-to-end ====
if len(sys.argv) > 2 and sys.argv[2] == 'fn8d6f4':
    # fresh unicorn
    mu2 = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu2.mem_map(0x0, 0x160000)
    mu2.mem_write(0x0, elf[:0x148e60])
    mu2.mem_write(0x14ce60, elf[0x148e60:0x148e60 + 0xdc0])
    mu2.mem_write(0x151c20, elf[0x149c20:0x149c20 + 0x360a])
    mu2.mem_map(STACK, 0x200000)
    mu2.mem_map(FAKE, 0x10000)
    mu2.mem_map(0x66600000, 0x1000)
    mu2.mem_write(0x66600000, struct.pack("<I", 0xD65F03C0) * 1024)
    mu2.mem_map(OBJ & ~0xFFF, 0x1000)
    ENV2 = FAKE + 0x1000
    FUNCS2 = FAKE + 0x2000
    mu2.mem_write(ENV2, struct.pack("<Q", FUNCS2))
    for slot in list(JNI_NAMES) + [0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x80]:
        mu2.mem_write(FUNCS2 + slot, struct.pack("<Q", MAGIC_BASE + slot))
    CTX = FAKE + 0x3000

    def hook2(uc, address, size, user_data):
        if MAGIC_BASE <= address < MAGIC_BASE + 0x1000:
            slot = address - MAGIC_BASE
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            nm = JNI_NAMES.get(slot, "slot_0x%x" % slot)
            if nm == "GetObjectClass":
                trace.append("GetObjectClass(env, obj=0x%x)" % x1)
                uc.reg_write(UC_ARM64_REG_X0, FAKE + 0x30)
            elif nm == "GetFieldID":
                s2 = s3 = None
                try: s2 = rd_str2(uc, x2)
                except Exception: pass
                try: s3 = rd_str2(uc, x3)
                except Exception: pass
                trace.append("GetFieldID(env, clazz, name=%r@0x%x, sig=%r@0x%x)" % (s2, x2, s3, x3))
                uc.reg_write(UC_ARM64_REG_X0, FAKE + 0x40)
            elif nm == "GetIntField":
                trace.append("GetIntField(env, obj=0x%x, fid=0x%x) -> 0x2a" % (x1, x2))
                uc.reg_write(UC_ARM64_REG_X0, 0x2A)
            elif nm == "GetObjectField":
                trace.append("GetObjectField(env, obj=0x%x, fid=0x%x) -> fakestr" % (x1, x2))
                uc.reg_write(UC_ARM64_REG_X0, OBJ)
            elif nm == "GetMethodID":
                s2 = s3 = None
                try: s2 = rd_str2(uc, x2)
                except Exception: pass
                try: s3 = rd_str2(uc, x3)
                except Exception: pass
                trace.append("GetMethodID(env, clazz=0x%x, name=%r@0x%x, sig=%r@0x%x)" % (x1, s2, x2, s3, x3))
                uc.reg_write(UC_ARM64_REG_X0, FAKE + 0x50)
            elif nm == "CallObjectMethod":
                trace.append("CallObjectMethod(env, obj=0x%x, mid=0x%x) -> fakestr" % (x1, x2))
                uc.reg_write(UC_ARM64_REG_X0, OBJ)
            elif nm == "ExceptionCheck":
                uc.reg_write(UC_ARM64_REG_X0, 0)
            elif nm == "DeleteLocalRef":
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                trace.append("%s(env, 0x%x, 0x%x, 0x%x)" % (nm, x1, x2, x3))
                uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if plt_start <= address < plt_start + plt_size:
            nm = PLT_NAME.get(address, "plt_0x%x" % address)
            a0 = uc.reg_read(UC_ARM64_REG_X0); a1 = uc.reg_read(UC_ARM64_REG_X1); a2 = uc.reg_read(UC_ARM64_REG_X2)
            if nm in ("memcpy", "memmove"):
                uc.mem_write(a0, bytes(uc.mem_read(a1, a2))); uc.reg_write(UC_ARM64_REG_X0, a0)
            elif nm == "memset":
                uc.mem_write(a0, bytes([a2 & 0xFF]) * a1); uc.reg_write(UC_ARM64_REG_X0, a0)
            elif nm in ("malloc", "calloc"):
                uc.reg_write(UC_ARM64_REG_X0, FAKE + 0x8000)
            elif nm == "__system_property_get":
                try:
                    nmstr = rd_str2(uc, a0)
                except Exception:
                    nmstr = "?"
                val = b"emu\x00"
                uc.mem_write(a1, val)
                trace.append("property_get(%r @0x%x) -> 'emu'" % (nmstr, a0))
                uc.reg_write(UC_ARM64_REG_X0, 3)
            else:
                trace.append("PLT %s(0x%x, 0x%x, 0x%x)" % (nm, a0, a1, a2))
                uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return

    def hook2_mem(uc, access, address, size, value, user_data):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        print("!! invalid mem 0x%x pc=0x%x" % (address, pc))
        if pc == address:
            for r in range(28):
                v = uc.reg_read(UC_ARM64_REG_X0 + r)
                if v:
                    print("   x%d = 0x%x" % (r, v))
        return False

    print("# mu2 relocations:", apply_relocs(mu2, [(0x0, 0x0, 0x160000)]))
    mu2.hook_add(UC_HOOK_CODE, hook2)
    mu2.hook_add(UC_HOOK_MEM_INVALID, hook2_mem)
    mu2.reg_write(UC_ARM64_REG_SP, STACK + 0x100000)
    mu2.reg_write(UC_ARM64_REG_X0, OBJ)      # bridge object (VM arg0)
    mu2.reg_write(UC_ARM64_REG_X1, ENV2)     # JNIEnv (VM arg2)
    mu2.reg_write(UC_ARM64_REG_X2, CTX)      # ctx (zeroed 0x878)
    mu2.reg_write(UC_ARM64_REG_X3, OBJ)      # VM arg3
    mu2.mem_write(FAKE + 0x400, struct.pack("<I", 0xD65F03C0))
    mu2.reg_write(UC_ARM64_REG_X30, FAKE + 0x400)
    try:
        mu2.emu_start(0x8D6F4, FAKE + 0x3FF, timeout=0, count=60_000_000)
    except UcError as e:
        print("!! stopped: %s pc=0x%x" % (e, mu2.reg_read(UC_ARM64_REG_PC)))
    print("=== sub_8d6f4 JNI trace ===")
    for t in trace:
        print(t)
    import re as _re
    ctxbytes = bytes(mu2.mem_read(CTX, 0x878))
    print("ctx[0x60..0x70]:", ctxbytes[0x60:0x70].hex())
    raise SystemExit(0)

def rd_str2(uc, addr):
    out = b""
    for i in range(256):
        c = uc.mem_read(addr + i, 1)
        if c == b"\x00":
            break
        out += c
    return out.decode("latin1")

name_va = int(sys.argv[1], 16)
STATUS = FAKE + 0x100
OUTPTR = FAKE + 0x200
mu.mem_write(STATUS, b"\x00" * 8)
mu.mem_write(OUTPTR, b"\x00" * 8)

# sub_be168(x0=out_status, x1=env, x2=jobject, x3=name_blob, x4=out_slot)
mu.reg_write(UC_ARM64_REG_SP, STACK + 0x100000)
mu.reg_write(UC_ARM64_REG_X0, STATUS)
mu.reg_write(UC_ARM64_REG_X1, ENV)
mu.reg_write(UC_ARM64_REG_X2, OBJ)
mu.reg_write(UC_ARM64_REG_X3, name_va)
mu.reg_write(UC_ARM64_REG_X4, OUTPTR)
mu.reg_write(UC_ARM64_REG_X30, FAKE + 0x400)  # fake return addr

# put a stop sentinel at the fake return address
mu.mem_write(FAKE + 0x400, struct.pack("<I", 0xD65F03C0))  # ret


def hook_mem_invalid(uc, access, address, size, value, user_data):
    print("!! invalid mem access 0x%x size %d value 0x%x at pc 0x%x" %
          (address, size, value, uc.reg_read(UC_ARM64_REG_PC)))
    return False


mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

try:
    mu.emu_start(0xBE168, FAKE + 0x3FF, timeout=0, count=60_000_000)
except UcError as e:
    print("!! stopped: %s pc=0x%x" % (e, mu.reg_read(UC_ARM64_REG_PC)))

print("=== JNI/PLT trace for name blob 0x%x ===" % name_va)
for t in trace:
    print(t)
st = mu.mem_read(STATUS, 8)
op = mu.mem_read(OUTPTR, 8)
print("out_status bytes: %s" % st.hex())
print("out_slot value: 0x%s" % op[::-1].hex())
print("final w0 = 0x%x" % (mu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF))
