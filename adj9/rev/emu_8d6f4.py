"""emu_8d6f4.py - emulate libsigner.so's signing path under Unicorn with a
programmable JNIEnv / PLT / syscall environment.

Extension of emu_be168.py (yesterday's harness).  Emulates the FULL path
nSign (0xdb1cc) -> 0x95fc4 -> VM interpreter (0xfb00) -> sub_8d6f4 (region
builder) with:
  * a standard JNIEnv 1.6 function table (all 233 slots) with semantic
    stubs: GetObjectClass/GetFieldID/GetIntField (widthPixels=1080,
    heightPixels=2400), map.get backed by a per-key value table (android_id
    and fire_adid = null, matching device captures), getPackageName, the
    signatures/signingInfo/getSigningCertificateHistory/toByteArray cert
    chain, MessageDigest SHA-1 update/digest (returns cfg cert_sha1),
    NewStringUTF on decrypted key blobs, ...
  * a JavaVM table (AttachCurrentThread/DetachCurrentThread/GetEnv),
  * PLT stubs for all 73 imports (malloc/calloc = deterministic bump
    allocator, __system_property_get with device-real semantics: absent
    property -> length 0, qemu probes fail like a real device),
  * a pthread_create model: threads are DEFERRED and run as COROUTINES
    (full register save/restore + separate stack) handed control when the
    main VM spins on its dispatch tag (0x18810) or when the builder polls
    (0x8d364), so the two-thread cooperative VM can progress,
  * a virtual clock: clock_gettime/gettimeofday return cfg base + 1 ms per
    call so timed waits terminate; the base (sec/nsec/usec) is a controlled
    experiment input.

Findings (see emu_findings.md): the builder path is byte-for-byte
deterministic for identical inputs; the per-call-varying source in the whole
pipeline is the FINE CLOCK (CLOCK_MONOTONIC read by a VM opcode at 0x18aa0 +
CLOCK_REALTIME/gettimeofday in the nSign preamble); varying clock_gettime
nsec by +-1 ns flips ctx words +0x718/+0x788 (region-adjacent hash state),
while tid/pid/srand/usec/second flip nothing.

Usage:
  python emu_8d6f4.py                     # one baseline run + stage report
  python emu_8d6f4.py --runs 2 --digest   # twice-run identical-input verdict
  python emu_8d6f4.py --sens              # one-at-a-time input sensitivity map
  python emu_8d6f4.py --dump-trace        # dump the full call log to JSON
"""
import argparse
import json
import os
import struct
import sys
import time as pytime

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import *
from unicorn.arm64_const import *

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "..", "extracted", "arm64", "lib", "arm64-v8a", "libsigner.so")

# ---------------------------------------------------------------- ELF parsing
elf = open(LIB, "rb").read()
e_shoff = struct.unpack_from("<Q", elf, 0x28)[0]
e_shentsize = struct.unpack_from("<H", elf, 0x3A)[0]
e_shnum = struct.unpack_from("<H", elf, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", elf, 0x3E)[0]


def _sh(i):
    return struct.unpack_from("<IIQQQQIIQQ", elf, e_shoff + i * e_shentsize)


stro = _sh(e_shstrndx)[4]
SECS = {}
for _i in range(e_shnum):
    _s = _sh(_i)
    _nm = elf[stro + _s[0]:elf.index(b"\x00", stro + _s[0])].decode()
    SECS[_nm] = _s

_dynsym = SECS[".dynsym"]
_dynstr = SECS[".dynstr"]


def sym_name(idx):
    o = _dynsym[4] + idx * 24
    st_name = struct.unpack_from("<I", elf, o)[0]
    e = elf.index(b"\x00", _dynstr[4] + st_name)
    return elf[_dynstr[4] + st_name:_dynstr[4] + st_name + e - _dynstr[4] - st_name].decode()


plt_syms = {}
ro = SECS[".rela.plt"][4]
for _i in range(SECS[".rela.plt"][5] // 24):
    off, info, _add = struct.unpack_from("<QQq", elf, ro + _i * 24)
    plt_syms[off] = sym_name(info >> 32)

plt_start = SECS[".plt"][3]
plt_size = SECS[".plt"][5]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
mdd = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
mdd.detail = True
got_to_plt = {}
for _ent in range(1, plt_size // 16):
    _addr = plt_start + _ent * 16
    _got = None
    _adrp = None
    for ins in mdd.disasm(elf[_addr:_addr + 16], _addr):
        if ins.mnemonic == "adrp":
            _adrp = ins.operands[1].imm
        elif ins.mnemonic == "ldr" and _adrp is not None:
            _got = _adrp + ins.operands[-1].mem.disp
            break
    if _got:
        got_to_plt[_got] = _addr
PLT_NAME = {p: plt_syms[g] for g, p in got_to_plt.items() if g in plt_syms}

# ------------------------------------------------------------ constants/areas
STACK = 0x30000000000
FAKE = 0x40000000000          # scratch: env, handles, buffers
FAKE_SZ = 0x100000
MAGIC = 0x66600000            # JNI trampoline page
OBJBASE = 0x52000000000       # fake java objects
HEAP = 0x53000000000          # malloc/calloc arena
THSTK = 0x55000000000         # thread stacks (map 8 MB)
MMAP = 0x54000000000          # mmap arena
WORKER_STACK_BASE = 0x30000000000   # lower half of stack map: worker stacks
STOP = FAKE + 0x400           # fake return address (holds 'ret')

# standard JNIEnv 1.6 slot names (offset = index*8), built programmatically
def _build_jni_names():
    names = {}
    base = ["reserved0", "reserved1", "reserved2", "reserved3", "GetVersion",
            "DefineClass", "FindClass", "FromReflectedMethod", "FromReflectedField",
            "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom", "ToReflectedField",
            "Throw", "ThrowNew", "ExceptionOccurred", "ExceptionDescribe",
            "ExceptionClear", "FatalError", "PushLocalFrame", "PopLocalFrame",
            "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef", "IsSameObject",
            "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject",
            "NewObjectV", "NewObjectA", "GetObjectClass", "IsInstanceOf", "GetMethodID"]
    for i, n in enumerate(base):
        names[i * 8] = n
    types = "Object Boolean Byte Char Short Int Long Float Double Void".split()
    idx = 34
    for t in types:                       # Call<Type>Method, V, A
        names[idx * 8] = "Call%sMethod" % t
        names[(idx + 1) * 8] = "Call%sMethodV" % t
        names[(idx + 2) * 8] = "Call%sMethodA" % t
        idx += 3
    for t in types:                       # CallNonvirtual<Type>Method, V, A
        names[idx * 8] = "CallNonvirtual%sMethod" % t
        names[(idx + 1) * 8] = "CallNonvirtual%sMethodV" % t
        names[(idx + 2) * 8] = "CallNonvirtual%sMethodA" % t
        idx += 3
    tail = ["GetFieldID", "GetObjectField", "GetBooleanField", "GetByteField",
            "GetCharField", "GetShortField", "GetIntField", "GetLongField",
            "GetFloatField", "GetDoubleField", "SetObjectField", "SetBooleanField",
            "SetByteField", "SetCharField", "SetShortField", "SetIntField",
            "SetLongField", "SetFloatField", "SetDoubleField", "GetStaticMethodID"]
    for n in tail:
        names[idx * 8] = n
        idx += 1
    for t in types:                       # CallStatic<Type>Method, V, A
        names[idx * 8] = "CallStatic%sMethod" % t
        names[(idx + 1) * 8] = "CallStatic%sMethodV" % t
        names[(idx + 2) * 8] = "CallStatic%sMethodA" % t
        idx += 3
    tail2 = ["GetStaticFieldID", "GetStaticObjectField", "GetStaticBooleanField",
             "GetStaticByteField", "GetStaticCharField", "GetStaticShortField",
             "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField",
             "GetStaticDoubleField", "SetStaticObjectField", "SetStaticBooleanField",
             "SetStaticByteField", "SetStaticCharField", "SetStaticShortField",
             "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField",
             "SetStaticDoubleField", "NewString", "GetStringLength", "GetStringChars",
             "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength",
             "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength",
             "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement",
             "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray",
             "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray",
             "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements",
             "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements",
             "GetFloatArrayElements", "GetDoubleArrayElements",
             "ReleaseBooleanArrayElements", "ReleaseByteArrayElements",
             "ReleaseCharArrayElements", "ReleaseShortArrayElements",
             "ReleaseIntArrayElements", "ReleaseLongArrayElements",
             "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements",
             "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion",
             "GetShortArrayRegion", "GetIntArrayRegion", "GetLongArrayRegion",
             "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion",
             "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion",
             "SetIntArrayRegion", "SetLongArrayRegion", "SetFloatArrayRegion",
             "SetDoubleArrayRegion", "RegisterNatives", "UnregisterNatives",
             "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion",
             "GetStringUTFRegion", "GetPrimitiveArrayCritical",
             "ReleasePrimitiveArrayCritical", "GetStringCritical",
             "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef",
             "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress",
             "GetDirectBufferCapacity", "GetObjectRefType"]
    for n in tail2:
        names[idx * 8] = n
        idx += 1
    return names


JNI_NAMES = _build_jni_names()

# unicorn 2.1.4 enum trap: X29=1/X30=2 (alias slots) while X0..X28=199..227, so
# range(X0, X30+1) is EMPTY and any "save x0..x30" loop over it saves nothing.
XREGS = list(range(UC_ARM64_REG_X0, UC_ARM64_REG_X28 + 1)) + \
    [UC_ARM64_REG_X29, UC_ARM64_REG_X30]

# default configuration: every modeled input of a signing call
DEF_CFG = {
    "width": 1080,
    "height": 2400,
    "props": {
        "ro.product.manufacturer": "Xiaomi",
        "ro.product.model": "M2101K9G",
        "ro.product.device": "alioth",
        "ro.product.name": "alioth_in",
        "ro.build.fingerprint": "Xiaomi/alioth_in/alioth:12/SKQ1.211006.001/V13.0.6.0.SKHCNXM:user/release-keys",
        "ro.build.version.release": "12",
        "ro.build.version.sdk": "31",
        "ro.build.display.id": "SKQ1.211006.001 test keys",
        "ro.build.tags": "release-keys",
        "ro.build.type": "user",
        "ro.hardware": "qcom",
        "ro.board.platform": "lahaina",
        "ro.crypto.state": "encrypted",
    },
    "prop_default": "emu",
    "package": "com.penti.app",
    "strvals": {"secret_id": "s3cr3t", "client_sdk": "android5.7.0",
                "environment": "production", "app_version": "3.13.9",
                "android_id": None, "fire_adid": None,
                "default": "emu-string"},
    "hmac": bytes((i * 7 + 3) & 0xFF for i in range(32)),
    "cert": bytes((i * 13 + 5) & 0xFF for i in range(1054)),
    "cert_sha1": bytes((i * 11 + 1) & 0xFF for i in range(20)),
    "sec": 1789240512,        # clock_gettime seconds
    "nsec": 500000000,        # clock_gettime nanoseconds
    "time_sec": 1789240512,   # time()
    "usec": 500000,           # gettimeofday
    "mono_sec": None,         # if set: CLOCK_MONOTONIC base (clk_id==1)
    "mono_nsec": 0,           # CLOCK_MONOTONIC nanoseconds
    "pid": 12345,
    "tid": 12346,
    "tls_base": 0x111100000,
    "stack_guard": 0x1122334455667788,
    "srand_seed": 1,
    "rand_impl": "random3",   # bionic rand()=random()=BSD TYPE_3 (header law)
    "urandom8": None,         # if set (8 bytes): /dev/urandom read succeeds
                              # and returns these bytes in get8random;
                              # None = openat fails -> gettimeofday fallback
    "log_urandom_state": True, # dump the 0x143794/ctx_init seeded state
    "x3_is_hmac": True,       # pass an hmac byte[] as the 4th arg (VM arg3)
}


def cstr(uc, addr, maxn=512):
    out = b""
    for i in range(maxn):
        c = uc.mem_read(addr + i, 1)
        if c == b"\x00":
            break
        out += c
    return out.decode("latin1")


class Emu:
    def __init__(self, cfg=None, digest=False):
        self.cfg = dict(DEF_CFG)
        if cfg:
            self.cfg.update(cfg)
        self.log = []
        self.calls = []
        self.handles = {}          # addr -> dict(kind=..., ...)
        self.next_handle = OBJBASE + 0x100
        self.heap_next = HEAP
        self.alloc_sz = {}         # bump-block addr -> size (for realloc copy)
        self.heap_map_end = HEAP + 0x200000
        self.mmap_next = MMAP
        self.digest = digest
        self.digest_state = 0
        self.digest_ckpts = []
        self.icount = 0
        self.stopped = None
        self.mrs_log = []
        self.rand_state = self.cfg["srand_seed"] & 0xFFFFFFFF
        self.once_done = set()
        self.virt_ns = 0             # virtual clock offset (advances 1 ms per call)
        self.cori = {}               # coroutine name -> ctx ("fresh" tuple or saved regs)
        self._cur = "main"           # "main" + "th<N>"; main's ctx saved on first switch
        self._tick = 0
        self._nth = 0                # pthread counter (never reused -> no name clash)
        self._pending = None         # fresh coroutine to dispatch right after create
        self.rand_calls = []         # (index, value, return-site) for every rand()
        self.srand_log = []          # every srand() seed
        self.poll_log = []           # builder byte-poll observations at 0x8d364
        self.emit_log = []           # wire EMIT trace (x0, idx, value)
        self.pm_state = None
        self.result = {}             # x0/handle/blob at emu exit
        self._build()
        # cooperative scheduler time-slices at the two wait points
        self.mu.hook_add(UC_HOOK_CODE, self.hook_sched, begin=0x18810, end=0x18810)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_sched, begin=0x8D364, end=0x8D364)
        self._trail = []
        def _block(uc, address, size, ud):
            t = self._trail
            t.append(address)
            if len(t) > 60:
                del t[0]
        def _fault(uc, access, address, size, value, ud):
            import sys as _s
            print("[FAULT] access=%d addr=0x%x size=%d pc=0x%x cur=%s" % (
                access, address, size, uc.reg_read(UC_ARM64_REG_PC), self._cur), file=_s.stderr)
            print("[TRAIL] " + " ".join(hex(a) for a in self._trail[-40:]), file=_s.stderr)
            return False
        self.mu.hook_add(UC_HOOK_BLOCK, _block)
        self.mu.hook_add(UC_HOOK_MEM_INVALID, _fault)

    # ---------------- infra ----------------
    M31 = 2147483647

    def rand3_seed(self, seed):
        """bionic/OpenBSD srandom() TYPE_3: 31-word table, Park-Miller fill,
        310 outputs discarded (matches the proven Random3 header law)."""
        r = [0] * 31
        s = seed or 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        r[0] = w
        for i in range(1, 31):
            hi, lo = divmod(w, 127773)
            w = 16807 * lo - 2836 * hi
            if w < 0:
                w += self.M31
            r[i] = w
        self.rand_tbl = r
        self.rand_f, self.rand_b = 3, 0
        for _ in range(310):
            self.rand3_next()

    def rand3_next(self):
        r = self.rand_tbl
        v = (r[self.rand_f] + r[self.rand_b]) & 0xFFFFFFFF
        r[self.rand_f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.rand_f = (self.rand_f + 1) % 31
        self.rand_b = (self.rand_b + 1) % 31
        return o

    def alloc_handle(self, kind, **kw):
        a = self.next_handle
        self.next_handle += 0x40
        d = {"kind": kind}
        d.update(kw)
        self.handles[a] = d
        return a

    def bump(self, n, arena="heap"):
        n = (n + 15) & ~15
        if arena == "mmap":
            a = self.mmap_next
            self.mmap_next += (n + 0xFFF) & ~0xFFF
        else:
            a = self.heap_next
            self.heap_next += n
            # grow the heap mapping on demand (wire-builder VM reallocs a lot)
            if self.heap_next > self.heap_map_end:
                need = ((self.heap_next - self.heap_map_end
                         + 0xFFFF) // 0x10000) * 0x10000
                self.mu.mem_map(self.heap_map_end, need)
                self.heap_map_end += need
            self.alloc_sz[a] = n
        return a

    def _build(self):
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.mu = mu
        mu.mem_map(0x0, 0x160000)
        mu.mem_write(0x0, elf[:0x148e60])
        mu.mem_write(0x14ce60, elf[0x148e60:0x148e60 + 0xdc0])
        mu.mem_write(0x151c20, elf[0x149c20:0x149c20 + 0x360a])
        mu.mem_map(STACK, 0x200000)
        mu.mem_map(FAKE, FAKE_SZ)
        mu.mem_map(MAGIC, 0x1000)
        mu.mem_write(MAGIC, struct.pack("<I", 0xD65F03C0) * 256)
        mu.mem_map(OBJBASE, 0x100000)
        mu.mem_map(HEAP, 0x200000)
        mu.mem_map(THSTK, 0x800000)
        mu.mem_map(MMAP, 0x200000)
        # TLS block for mrs tpidr_el0 (stack guard at +0x28, bionic layout)
        mu.mem_map(self.cfg["tls_base"] & ~0xFFF, 0x4000)
        mu.mem_write(self.cfg["tls_base"] + 0x28,
                     struct.pack("<Q", self.cfg["stack_guard"]))
        mu.reg_write(UC_ARM64_REG_TPIDR_EL0, self.cfg["tls_base"])
        # JNIEnv
        self.ENV = FAKE + 0x1000
        self.FUNCS = FAKE + 0x2000
        mu.mem_write(self.ENV, struct.pack("<Q", self.FUNCS))
        self.VM = FAKE + 0x80          # fake JavaVM
        self.VMFUNCS = FAKE + 0x90
        mu.mem_write(self.VM, struct.pack("<Q", self.VMFUNCS))
        # JavaVM table (Android arm64 layout: 0x20 AttachCurrentThread,
        # 0x28 DetachCurrentThread, 0x30 GetEnv, 0x38 DestroyJavaVM)
        for slot, val in ((0x20, MAGIC + 0x780), (0x28, MAGIC + 0x788),
                          (0x30, MAGIC + 0x790), (0x38, MAGIC + 0x798)):
            mu.mem_write(self.VMFUNCS + slot, struct.pack("<Q", val))
        for slot in range(0x20, 0x6D8 + 8, 8):
            mu.mem_write(self.FUNCS + slot, struct.pack("<Q", MAGIC + slot))
        self.CTX = FAKE + 0x20000      # used only in standalone 8d6f4 mode
        self.ctx_seen = []             # ctx pointers observed at 0xfb64
        self.OBJ = self.alloc_handle("object", name="<payload>")
        self.OBJ_STR = self.alloc_handle("string", data=self.cfg["strvals"]["default"])
        self.OBJ_HMAC = self.alloc_handle("bytearray", size=len(self.cfg["hmac"]))
        ha = self.bump(len(self.cfg["hmac"]))
        mu.mem_write(ha, self.cfg["hmac"])
        self.handles[self.OBJ_HMAC]["back"] = ha
        # nSign's java arguments (static native: env, clazz, ctx, map, hmac, sdkInt)
        self.CLAZZ = self.alloc_handle("class", name="NativeLibHelper")
        self.CTXOBJ = self.alloc_handle("object", name="Context")
        self.MAPOBJ = self.alloc_handle("object", name="LinkedHashMap")
        # trace the VM -> builder call to learn the real ctx pointer
        mu.hook_add(UC_HOOK_CODE, self.hook_fb64, begin=0xFB50, end=0xFB68)
        # wire-builder diagnostics: merge section lengths + PM state
        mu.hook_add(UC_HOOK_CODE, self.hook_merge, begin=0x129220, end=0x129220)
        mu.hook_add(UC_HOOK_CODE, self.hook_pmstate, begin=0x1437C8, end=0x1437C8)
        if self.cfg.get("trace_emits"):
            mu.hook_add(UC_HOOK_CODE, self.hook_emit, begin=0x147630, end=0x147630)

        self.nrel = self.apply_relocs()

        mu.hook_add(UC_HOOK_CODE, self.hook_jni, begin=MAGIC, end=MAGIC + 0xFFF)
        mu.hook_add(UC_HOOK_CODE, self.hook_plt, begin=plt_start, end=plt_start + plt_size - 1)
        mu.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
        mu.hook_add(UC_HOOK_INTR, self.hook_intr)
        try:
            mu.hook_add(UC_HOOK_INSN, self.hook_mrs, begin=1, end=0, arg1=UC_ARM64_INS_MRS)
        except Exception as e:
            self.log.append("!! MRS hook unavailable: %s" % e)
        if self.digest:
            mu.hook_add(UC_HOOK_CODE, self.hook_digest)

    def apply_relocs(self):
        d = SECS[".rela.dyn"]
        off, size = d[4], d[5]
        n = 0
        for i in range(size // 24):
            r_off, r_info, r_add = struct.unpack_from("<QQq", elf, off + i * 24)
            if (r_info & 0xFFFFFFFF) == 0x403:
                self.mu.mem_write(r_off, struct.pack("<Q", r_add & (2**64 - 1)))
                n += 1
        return n

    # ---------------- hooks ----------------
    def hook_digest(self, uc, address, size, ud):
        self.icount += 1
        self.digest_state = (self.digest_state * 1000003 + address) & 0xFFFFFFFFFFFFFFFF
        if self.icount % (1 << 21) == 0:
            self.digest_ckpts.append((self.icount, self.digest_state))

    def hook_mem_invalid(self, uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        kind = {1: "READ", 2: "WRITE", 3: "FETCH", 4: "READ_UNALIGNED",
                5: "WRITE_UNALIGNED", 6: "FETCH_UNALIGNED"}.get(access, str(access))
        self.stopped = "invalid mem %s 0x%x size %d pc=0x%x" % (kind, address, size, pc)
        self.log.append("!! " + self.stopped)
        return False

    def hook_mrs(self, uc, access, ud):
        # intercept MRS: log it; for tpidr_el0 let unicorn do the default
        pc = uc.reg_read(UC_ARM64_REG_PC)
        try:
            ins = next(md.disasm(bytes(uc.mem_read(pc, 4)), pc))
            self.mrs_log.append((pc, ins.op_str))
            if "cntvct" in ins.op_str or "cntpct" in ins.op_str:
                # write fake counter value into the destination reg
                from capstone.arm64 import ARM64_REG_X0
                ops = ins.operands
                if ops and ops[0].type == ARM64_REG_X0:
                    uc.reg_write(UC_ARM64_REG_X0 + (ops[0].reg - ARM64_REG_X0),
                                 self.cfg.get("cntvct", 0))
                    return True
        except Exception:
            pass
        return False

    def hook_intr(self, uc, intno, ud):
        # ARM64 SVC: x8 = syscall number
        num = uc.reg_read(UC_ARM64_REG_X8)
        a0 = uc.reg_read(UC_ARM64_REG_X0)
        a1 = uc.reg_read(UC_ARM64_REG_X1)
        a2 = uc.reg_read(UC_ARM64_REG_X2)
        ret = self.do_syscall(num, a0, a1, a2, via="svc")
        uc.reg_write(UC_ARM64_REG_X0, ret & (2**64 - 1))
        return

    def hook_fb64(self, uc, address, size, ud):
        if address == 0xFB64:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            self.ctx_seen.append((x0, x1, x2, x3))
            self.log.append("VM->builder 0xfb64: x0=0x%x x1=0x%x ctx=0x%x x3=0x%x"
                            % (x0, x1, x2, x3))

    def hook_merge(self, uc, address, size, ud):
        """0x129220: bl OUTLEN(stream) — log every wire sink's section len."""
        try:
            x20 = uc.reg_read(UC_ARM64_REG_X20)
            lens = []
            for k in range(-2, 20):
                wp = struct.unpack("<Q", bytes(uc.mem_read(x20 + k * 8 + 0x20, 8)))[0]
                if not (HEAP <= wp < HEAP + 0x1000000 or
                        (0x50000000000 <= wp < 0x56000000000)):
                    lens.append(None)
                    continue
                acc = struct.unpack("<I", bytes(uc.mem_read(wp + 0x10, 4)))[0]
                n = struct.unpack("<I", bytes(uc.mem_read(wp + 0x14, 4)))[0]
                tops = struct.unpack("<Q", bytes(uc.mem_read(wp + 0x18, 8)))[0]
                top = struct.unpack("<I", bytes(uc.mem_read(tops + 4 * (n - 1), 4)))[0] if n else 0
                lens.append((k, acc - top, acc, top))
            self.merge_lens = lens
            self.calls.append(("merge_sink_lens", lens))
        except UcError:
            pass

    def hook_pmstate(self, uc, address, size, ud):
        """0x1437c8: right after ctx_init — the 0x143794 chain's seeded state."""
        try:
            x19 = uc.reg_read(UC_ARM64_REG_X19)
            st = bytes(uc.mem_read(x19, 0x18))
            self.pm_state = st
            self.calls.append(("pm_state", hex(x19), st.hex()))
        except UcError:
            pass

    def hook_emit(self, uc, address, size, ud):
        """0x147630 = push(writer, value, idx): wire EMIT trace."""
        try:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            self.emit_log.append((x0, x2, x1))
        except UcError:
            pass

    # ------------- cooperative scheduler -------------
    # Threads run CONCURRENTLY on the device, so a fresh coroutine is
    # dispatched immediately at pthread_create (hook_plt -> _dispatch_new)
    # and control comes back at yield points: the two hot waits (VM dispatch
    # tag 0x18810, builder byte-poll 0x8d364, quantum-gated) and every
    # clock_gettime/gettimeofday/time PLT call (a natural block point).
    QUANTUM = 1000          # wait-point passes per time slice

    def hook_sched(self, uc, address, size, ud):
        self._tick += 1
        if address == 0x8D364:
            # observe the builder's byte-poll: x8 should be ctx+0x818
            try:
                x8 = uc.reg_read(UC_ARM64_REG_X8)
                b = uc.mem_read(x8, 1)[0]
                if len(self.poll_log) < 40 or b:
                    self.poll_log.append((len(self.poll_log), x8, b))
            except UcError:
                self.poll_log.append((len(self.poll_log),
                                      uc.reg_read(UC_ARM64_REG_X8), None))
        if len(self.cori) > 1 and self._tick % self.QUANTUM == 0:
            self._switch(uc, address)

    def _next_name(self):
        names = list(self.cori)
        i = names.index(self._cur) if self._cur in names else -1
        return names[(i + 1) % len(names)]

    def _switch(self, uc, resume_pc):
        if len(self.cori) <= 1:
            return
        self.cori[self._cur] = self._save_ctx(uc, resume_pc)
        self._cur = self._next_name()
        self._launch(uc)

    def _dispatch_new(self, uc):
        """Right after a pthread_create PLT return: launch the new thread."""
        name = self._pending
        self._pending = None
        self.cori[self._cur] = self._save_ctx(uc, uc.reg_read(UC_ARM64_REG_PC))
        self._cur = name
        self._launch(uc)

    def _save_ctx(self, uc, resume_pc):
        sv = {"x": {}, "v": {}, "sp": uc.reg_read(UC_ARM64_REG_SP),
              "nzcv": uc.reg_read(UC_ARM64_REG_NZCV),
              "ret": resume_pc}
        for r in XREGS:
            sv["x"][r] = uc.reg_read(r)
        for r in range(UC_ARM64_REG_V0, UC_ARM64_REG_V31 + 1):
            sv["v"][r] = uc.reg_read(r)
        return sv

    def _restore_ctx(self, uc, sv):
        for r, v in sv["x"].items():
            uc.reg_write(r, v)
        for r, v in sv["v"].items():
            uc.reg_write(r, v)
        uc.reg_write(UC_ARM64_REG_SP, sv["sp"])
        uc.reg_write(UC_ARM64_REG_NZCV, sv["nzcv"])
        uc.reg_write(UC_ARM64_REG_PC, sv["ret"])

    def _launch(self, uc):
        c = self.cori[self._cur]
        self._tick = 0
        if "fresh" in c:
            start, arg, stk = c.pop("fresh")
            for r in XREGS:
                uc.reg_write(r, 0)
            uc.reg_write(UC_ARM64_REG_NZCV, 0)
            uc.reg_write(UC_ARM64_REG_SP, stk)
            uc.reg_write(UC_ARM64_REG_X0, arg)
            uc.reg_write(UC_ARM64_REG_LR, MAGIC + 0x890)
            uc.reg_write(UC_ARM64_REG_PC, start)
        else:
            self._restore_ctx(uc, c)

    def hook_jni(self, uc, address, size, ud):
        slot = address - MAGIC
        if slot == 0x890:              # thread-return stub: coroutine finished
            self.calls.append(("THREAD-DONE", self._cur, ()))
            del self.cori[self._cur]
            if self.cori:
                self._cur = "main" if "main" in self.cori else next(iter(self.cori))
                self._launch(uc)
            else:                      # nothing left to run
                self.stopped = self.stopped or "all-coroutines-done"
                uc.emu_stop()
            return
        if slot >= 0x780:              # JavaVM table / trampolines
            if slot not in (0x780, 0x788, 0x790, 0x798):
                return                  # trampoline page area - just execute
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            nm = {0x780: "AttachCurrentThread", 0x788: "DetachCurrentThread",
                  0x790: "GetEnv", 0x798: "DestroyJavaVM"}[slot]
            if nm in ("AttachCurrentThread", "GetEnv"):
                if x1:
                    uc.mem_write(x1, struct.pack("<Q", self.ENV))
                self.calls.append(("javavm", nm, ()))
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                self.calls.append(("javavm", nm, ()))
                uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x3 = uc.reg_read(UC_ARM64_REG_X3)
        nm = JNI_NAMES.get(slot, "slot_0x%x" % slot)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        ret = self.jni(nm, slot, x1, x2, x3, uc, lr)
        uc.reg_write(UC_ARM64_REG_X0, ret & (2**64 - 1))
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def hook_plt(self, uc, address, size, ud):
        nm = PLT_NAME.get(address, "plt_0x%x" % address)
        a = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                      UC_ARM64_REG_X3)]
        self.last_plt_lr = uc.reg_read(UC_ARM64_REG_LR)
        ret = self.plt(nm, a, uc)
        if ret is None:                     # handler redirected PC itself
            return
        uc.reg_write(UC_ARM64_REG_X0, ret & (2**64 - 1))
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
        # cooperative scheduler: dispatch a just-created thread immediately,
        # and treat clock calls as yield points (they are where timed waits spin)
        if self._pending:
            self._dispatch_new(uc)
        elif nm in ("clock_gettime", "gettimeofday", "time") and len(self.cori) > 1:
            self._switch(uc, uc.reg_read(UC_ARM64_REG_PC))

    def _clock_pair(self, clk, off=0):
        """(sec, nsec) for a clock_gettime clk_id with the virtual offset."""
        if clk == 1 and self.cfg.get("mono_sec") is not None:
            base_s, base_ns = self.cfg["mono_sec"], self.cfg["mono_nsec"]
        else:
            base_s, base_ns = self.cfg["sec"], self.cfg["nsec"]
        ns = base_ns + off
        sec = base_s + ns // 1_000_000_000
        return sec, ns % 1_000_000_000

    # ---------------- syscall layer ----------------
    def do_syscall(self, num, a0, a1, a2, via="syscall"):
        mu = self.mu
        NAMES = {48: "faccessat", 56: "openat", 57: "close", 63: "read", 64: "write",
                 78: "readlinkat", 80: "fstat", 93: "exit", 113: "clock_gettime",
                 129: "kill", 160: "uname", 172: "getpid", 178: "gettid",
                 222: "mmap", 226: "mprotect", 233: "madvise"}
        nm = NAMES.get(num, "sys%d" % num)
        if num == 178:                      # gettid
            self.calls.append(("syscall", nm, []))
            return self.cfg["tid"]
        if num == 172:                      # getpid
            return self.cfg["pid"]
        if num == 113:                      # clock_gettime(clk, tp)
            s, ns = self._clock_pair(a0)
            mu.mem_write(a1, struct.pack("<ii", s, ns))
            self.calls.append(("syscall", "clock_gettime", [a0]))
            return 0
        if num == 57:                       # close
            return 0
        if num == 56:                       # openat (via the syscall PLT)
            if self.cfg.get("urandom8"):
                try:
                    p = cstr(mu, a1)
                except Exception:
                    p = "?"
                if "urandom" in p:
                    self.calls.append(("syscall", "openat_urandom", p))
                    self._urandom_fd = 0x1234
                    return self._urandom_fd           # fake fd
            self.calls.append(("syscall", "openat", [a1]))
            return -1
        if num in (63, 64, 78):             # read/write/readlinkat -> fail
            if num == 63 and self.cfg.get("urandom8") and \
                    a0 == getattr(self, "_urandom_fd", None):
                # raw-svc read of /dev/urandom (8 bytes; the low 32 bits seed
                # the 0x143794 ctx-init chain)
                mu.mem_write(a1, self.cfg["urandom8"][:8])
                self.calls.append(("syscall", "read_urandom", a1))
                return 8
            return -1
        if num == 222:                      # mmap
            n = a1
            addr = self.bump(max(n, 0x1000), "mmap")
            return addr
        self.calls.append(("syscall", nm, [a0]))
        return -1

    # ---------------- PLT layer ----------------
    def plt(self, nm, a, uc):
        mu = self.mu
        x0, x1, x2, x3 = a
        if nm in ("memcpy", "memmove"):
            if x2:
                mu.mem_write(x0, bytes(mu.mem_read(x1, x2)))
            return x0
        if nm == "__memcpy_chk":
            mu.mem_write(x0, bytes(mu.mem_read(x1, x2)))
            return x0
        if nm == "memset":
            # ARM64 memset(void *s, int c, size_t n): x0=dst, x1=ch, x2=n.
            # (was: bytes([x2 & 0xFF]) * x1 — swapped, making the builder's
            # memset(ctx,0,0x878) a no-op and leaving dead-frame junk that the
            # haystack-cell walk then dereferenced -> 0x8d364 fault)
            mu.mem_write(x0, bytes([x1 & 0xFF]) * x2)
            return x0
        if nm in ("strlen", "__strlen_chk"):
            n = 0
            try:
                while mu.mem_read(x0 + n, 1) != b"\x00":
                    n += 1
                    if n > 0x10000:
                        break
            except UcError:
                pass
            return n
        if nm == "strdup":
            n = self.plt("strlen", [x0], uc)
            dst = self.bump(n + 1)
            mu.mem_write(dst, bytes(mu.mem_read(x0, n + 1)))
            return dst
        if nm in ("strcmp", "strncmp"):
            try:
                s1 = cstr(uc, x0, 256)
                s2 = cstr(uc, x1, 256)
            except Exception:
                return 1
            if nm == "strncmp" and x2 < max(len(s1), len(s2)):
                s1, s2 = s1[:x2], s2[:x2]
            return 0 if s1 == s2 else (1 if s1 > s2 else (2**64 - 1))
        if nm == "strchr" or nm == "strchrnul":
            try:
                s = cstr(uc, x0, 4096)
            except Exception:
                return 0
            ch = chr(x1 & 0xFF)
            i = s.find(ch)
            if i < 0:
                return x0 + len(s) if nm == "strchrnul" else 0
            return x0 + i
        if nm in ("malloc", "calloc"):
            n = x0 if nm == "malloc" else x0 * x1
            n = max(n, 1) & 0xFFFFFFFF
            dst = self.bump(n)
            return dst
        if nm == "realloc":
            n = max(x1, 1)
            dst = self.bump(n)
            old = self.alloc_sz.get(x0)
            if old:
                keep = min(old, n)
                try:
                    mu.mem_write(dst, bytes(mu.mem_read(x0, keep)))
                except UcError:
                    pass
            return dst
        if nm == "free":
            return 0
        if nm == "__system_property_get":
            try:
                name = cstr(uc, x0)
            except Exception:
                name = "?"
            if name in self.cfg["props"]:
                val = self.cfg["props"][name]
                b = val.encode() + b"\x00"
                mu.mem_write(x1, b)
                self.calls.append(("prop", name, val))
                return len(val)
            self.calls.append(("prop", name, "<absent>"))
            return 0          # absent property: length 0, buffer untouched
        if nm == "clock_gettime":
            # virtual clock: advances 1 ms per call so poll-waits terminate.
            # clk_id split: CLOCK_MONOTONIC (1) uses the mono_* base when set
            # (device boot-relative ~3565 s at the captured signings), every
            # other clock uses the realtime base (sec/nsec).
            off = self.virt_ns
            self.virt_ns += 1_000_000
            sec, ns = self._clock_pair(x0, off)
            mu.mem_write(x1, struct.pack("<ii", sec, ns))
            self.calls.append(("clock_gettime", x0, (sec, ns), "0x%x" % self.last_plt_lr))
            return 0
        if nm == "gettimeofday":
            off = self.virt_ns
            self.virt_ns += 1_000_000
            us = self.cfg["usec"] + off // 1000
            sec = self.cfg["sec"] + us // 1_000_000
            us %= 1_000_000
            mu.mem_write(x0, struct.pack("<qq", sec, us))
            self.calls.append(("gettimeofday", [], (sec, us), "0x%x" % self.last_plt_lr))
            return 0
        if nm == "time":
            off = self.virt_ns
            self.virt_ns += 1_000_000
            t = self.cfg["time_sec"] + off // 1_000_000_000
            if x0:
                mu.mem_write(x0, struct.pack("<q", t))
            self.calls.append(("time", [], t, "0x%x" % self.last_plt_lr))
            return t
        if nm == "getpid":
            return self.cfg["pid"]
        if nm == "syscall":
            ret = self.do_syscall(x0, x1, x2, x3, via="plt")
            self.calls.append(("syscall", "nr%d" % x0, [x1, x2, x3]))
            return ret
        if nm == "rand":
            lr = mu.reg_read(UC_ARM64_REG_LR)
            impl = self.cfg.get("rand_impl", "random3")
            if impl == "lrand48":
                self.rand_state = ((self.rand_state * 0x5DEECE66D + 0xB)
                                   & ((1 << 48) - 1))
                v = self.rand_state >> 17
            elif impl == "random3":
                # bionic rand() == random() == BSD TYPE_3 additive feedback
                v = self.rand3_next()
            else:
                self.rand_state = (self.rand_state * 1103515245 + 12345) & 0x7FFFFFFF
                v = self.rand_state
            self.rand_calls.append((len(self.rand_calls), v, lr))
            self.calls.append(("rand", [], v))
            return v
        if nm == "srand":
            self.srand_log.append(x0 & 0xFFFFFFFF)
            impl = self.cfg.get("rand_impl", "random3")
            if impl == "lrand48":
                self.rand_state = ((x0 & 0xFFFFFFFF) << 16 | 0x330E) & ((1 << 48) - 1)
            elif impl == "random3":
                self.rand3_seed(x0 & 0xFFFFFFFF)
            else:
                self.rand_state = x0 & 0xFFFFFFFF
            return 0
        if nm in ("fopen", "opendir"):
            try:
                path = cstr(uc, x0)
            except Exception:
                path = "?"
            fake = self.cfg.get("fake_files") or {}
            if path in fake:
                # model a successful open of a virtual file: content is
                # cfg fake_files[path] (bytes); readdir returns nothing
                h = self.bump(0x100)
                self.handles[h] = {"kind": "FILE", "path": path,
                                   "content": fake[path], "pos": 0}
                self.calls.append((nm, path, "FAKE-OK"))
                return h
            if path == "/proc/self/fd" and self.cfg.get("fd_count"):
                # opendir("/proc/self/fd") succeeds on a real device; the
                # code readdir()s it to count open fds (anti-tamper signal)
                h = self.bump(0x100)
                self.handles[h] = {"kind": "DIR", "path": path, "dirent_idx": 0,
                                   "back": self.bump(0x1000)}
                self.calls.append((nm, path, "DIR-OK"))
                return h
            self.calls.append((nm, path, "FAIL"))
            return 0
        if nm == "readdir":
            fh = self.handles.get(x0)
            if fh and fh.get("kind") == "DIR":
                i = fh.get("dirent_idx", 0)
                n = self.cfg.get("fd_count", 0)
                if i < n:
                    fh["dirent_idx"] = i + 1
                    # struct dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) name
                    name = str(i)
                    d = struct.pack("<QQHb", 0x1000 + i, i * 8,
                                    19 + len(name), 8) + name.encode() + b"\x00"
                    mu.mem_write(fh["back"], d)
                    return fh["back"]
                return 0
            return 0
        if nm == "access":
            # device-real: access("/dev/urandom", F_OK) succeeds when the
            # urandom8 knob is set (models the real device's world-readable
            # /dev/urandom); everything else fails like a sandboxed device
            if self.cfg.get("urandom8"):
                try:
                    p = cstr(uc, x0)
                except Exception:
                    p = "?"
                if "urandom" in p:
                    self.calls.append(("access", p, "OK"))
                    return 0
            return -1
        if nm in ("read", "fread", "fgets"):
            if nm == "read" and self.cfg.get("urandom8") and \
                    x0 == getattr(self, "_urandom_fd", None):
                # the read PLT is how get8random fetches /dev/urandom
                mu.mem_write(x1, self.cfg["urandom8"][:x2 if x2 <= 8 else 8])
                self.calls.append(("read_urandom", x1, 8))
                return 8
            fh = self.handles.get(x0)
            if fh and fh.get("kind") == "FILE":
                c = fh["content"]
                n = min(len(c) - fh["pos"], x2 if nm != "fgets" else len(c))
                if n > 0:
                    mu.mem_write(x1, c[fh["pos"]:fh["pos"] + n])
                    fh["pos"] += n
                    return n
                return 0
            return 0 if nm != "read" else -1
        if nm in ("fclose", "closedir", "fseek", "ftell", "sscanf", "strftime",
                  "timer_create", "timer_settime", "pthread_condattr_init",
                  "pthread_condattr_setclock", "pthread_condattr_destroy",
                  "pthread_cond_init", "pthread_detach", "pthread_cond_signal",
                  "pthread_cond_broadcast", "pthread_cond_wait",
                  "pthread_cond_timedwait", "pthread_mutex_lock",
                  "pthread_mutex_unlock", "munmap", "UnregisterNatives"):
            return 0
        if nm == "fstat" or nm == "stat":
            return -1
        if nm == "mmap":
            return self.bump(max(x1, 0x1000), "mmap")
        if nm == "pthread_once":
            if x0 not in self.once_done:
                self.once_done.add(x0)
                mu.reg_write(UC_ARM64_REG_PC, x1)   # call the init fn, LR unchanged
                return None                          # None -> don't touch PC/ret
            return 0
        if nm == "pthread_create":
            start, arg = x2, x3
            if not hasattr(self, "thstk_next"):
                self.thstk_next = THSTK
            self.thstk_next += 0x80000
            stk = self.thstk_next - 0x1000
            self._nth += 1
            name = "th%d" % self._nth
            self.cori[name] = {"fresh": (start, arg, stk)}
            self._pending = name     # hook_plt dispatches it right after return
            self.calls.append(("pthread_create", hex(start), name))
            return 0
        if nm == "__errno":
            p = FAKE + 0x600
            mu.mem_write(p, b"\x00" * 8)
            return p
        if nm == "getauxval":
            return 0
        if nm == "localtime":
            t = self.cfg["time_sec"]
            import datetime
            dt = datetime.datetime.utcfromtimestamp(t)
            fmt = "<9iQQ" if False else "<9ixxxxQQ"  # 9 ints + pad + gmtoff + zone
            buf = struct.pack("<9i", dt.second, dt.minute, dt.hour, dt.day,
                              dt.month - 1, dt.year - 1900, (dt.weekday() + 1) % 7,
                              dt.timetuple().tm_yday - 1, 0)
            mu.mem_write(x0, buf + b"\x00" * 16)
            return x0
        if nm in ("vsnprintf",):
            self.calls.append((nm, [], "EMPTY"))
            return 0
        if nm == "strtol":
            try:
                return int(cstr(uc, x0).strip() or "0", 10)
            except Exception:
                return 0
        if nm == "fmod":
            d0 = struct.unpack("<d", struct.pack("<Q", x0))[0]
            d1 = struct.unpack("<d", struct.pack("<Q", x1))[0]
            import math
            try:
                return struct.unpack("<Q", struct.pack("<d", math.fmod(d0, d1)))[0]
            except Exception:
                return 0
        if nm == "__stack_chk_fail":
            self.stopped = "__stack_chk_fail (stack cookie mismatch)"
            self.log.append("!! " + self.stopped)
            return 0
        if nm in ("__cxa_atexit", "__cxa_finalize", "__android_log_print", "write",
                  "socket", "sendto", "setsockopt", "connect", "recvfrom", "inet_aton",
                  "strncmp_"):
            self.calls.append((nm, a[:3], "STUB"))
            return 0
        self.calls.append((nm, a[:3], "UNHANDLED"))
        self.log.append("!! unhandled PLT %s(0x%x,0x%x,0x%x)" % (nm, x0, x1, x2))
        return 0

    # ---------------- JNI layer ----------------
    def jni(self, nm, slot, x1, x2, x3, uc, lr=0):
        mu = self.mu
        h = self.handles
        H = lambda a: h.get(a, {"kind": "?"})
        s1 = s2 = s3 = None
        if nm in ("GetFieldID", "GetStaticFieldID", "GetMethodID", "GetStaticMethodID",
                  "FindClass", "NewStringUTF", "ThrowNew"):
            try:
                s1 = cstr(uc, x1)
            except Exception:
                s1 = None
            try:
                s2 = cstr(uc, x2) if nm not in ("FindClass", "NewStringUTF", "ThrowNew") else None
            except Exception:
                s2 = None
            try:
                s3 = cstr(uc, x3) if nm in ("GetFieldID", "GetStaticFieldID",
                                            "GetMethodID", "GetStaticMethodID") else None
            except Exception:
                s3 = None

        if nm in ("GetFieldID", "GetStaticFieldID"):
            self.calls.append(("jni", nm, (s2, s3), "0x%x" % lr))
            fid = self.alloc_handle("field", name=s2, sig=s3, static=nm.startswith("GetStatic"))
            return fid
        if nm in ("GetMethodID", "GetStaticMethodID"):
            self.calls.append(("jni", nm, (s2, s3), "0x%x" % lr))
            mid = self.alloc_handle("method", name=s2, sig=s3,
                                    static=nm.startswith("GetStatic"))
            return mid
        if nm == "FindClass":
            self.calls.append(("jni", "FindClass", s1, "0x%x" % lr))
            return self.alloc_handle("class", name=s1)
        if nm == "GetObjectClass":
            k = H(x1)
            self.calls.append(("jni", "GetObjectClass", (k.get("kind"), k.get("name", k.get("data")))))
            return self.alloc_handle("class", name="<runtime-class>")
        if nm == "GetIntField":
            fname = H(x2).get("name")
            val = {"widthPixels": self.cfg["width"], "heightPixels": self.cfg["height"]}.get(fname, 0)
            self.calls.append(("jni", "GetIntField", (fname, val)))
            return val & 0xFFFFFFFF
        if nm == "GetStaticIntField":
            self.calls.append(("jni", "GetStaticIntField", (H(x2).get("name"),)))
            return 0
        if nm in ("GetObjectField", "GetStaticObjectField"):
            fname = H(x2).get("name")
            sig = H(x2).get("sig") or ""
            self.calls.append(("jni", nm, (fname, sig)))
            if "Ljava/lang/String;" in sig:
                val = self.cfg["strvals"].get(fname, self.cfg["strvals"].get("default"))
                if val is None:
                    return 0                  # device-faithful: null String
                return self.alloc_handle("string", data=val)
            if fname in ("signatures",):
                arr = self.alloc_handle("objectarray", size=1, elem="signature")
                return arr
            if fname in ("signingInfo",):
                return self.alloc_handle("object", name="SigningInfo")
            return self.alloc_handle("object", name=fname or "<field>")
        if nm in ("CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA",
                  "CallStaticObjectMethod", "CallStaticObjectMethodV",
                  "CallStaticObjectMethodA", "NewObject", "NewObjectA", "AllocObject"):
            mname = H(x2).get("name") if nm.startswith("Call") else None
            self.calls.append(("jni", nm, (mname, H(x1).get("kind"))))
            if mname == "getPackageName":
                return self.alloc_handle("string", data=self.cfg["package"])
            if mname in ("getClassName", "getMethodName") and \
                    H(x1).get("kind") == "stackframe":
                fr = H(x1).get("frame") or ("?", "?")
                data = fr[0] if mname == "getClassName" else fr[1]
                return self.alloc_handle("string", data=str(data))
            if mname == "get":
                key = H(x3)
                kname = key.get("data") if key.get("kind") == "string" else None
                self.calls.append(("mapget", kname, "0x%x" % lr))
                val = self.cfg["strvals"].get(kname, self.cfg["strvals"]["default"])
                if val is None:
                    return 0                      # Java map.get -> null
                return self.alloc_handle("string", data=val)
            if mname == "digest":
                ba = self.alloc_handle("bytearray", size=len(self.cfg["cert_sha1"]))
                back = self.bump(len(self.cfg["cert_sha1"]))
                mu.mem_write(back, self.cfg["cert_sha1"])
                h[ba]["back"] = back
                return ba
            if mname == "doFinal":
                # Mac.doFinal: the native recomputes HMAC(key2, canonical) on
                # the first call per process.  For a genuine signing this
                # equals the Java-passed arg3 H byte-for-byte; steady-state
                # signings reuse the cached result.  Model: return H.
                mac = self.cfg.get("mac_h") or self.cfg["hmac"]
                ba = self.alloc_handle("bytearray", size=len(mac))
                back = self.bump(len(mac))
                mu.mem_write(back, mac)
                h[ba]["back"] = back
                self.calls.append(("jni", "doFinal", (len(mac),)))
                return ba
            if mname == "getStackTrace":
                # Thread.currentThread().getStackTrace(): return the modelled
                # frame list (cfg "stack_frames", [(class, method), ...])
                frames = self.cfg.get("stack_frames") or []
                arr = self.alloc_handle("objectarray", size=len(frames),
                                        elem="stackframe", frames=list(frames))
                self.calls.append(("jni", "getStackTrace", (len(frames),)))
                return arr
            if mname == "getBytes":
                src = H(x1)
                if src.get("kind") == "string":
                    data = src["data"].encode()
                else:
                    data = self.cfg["strvals"]["default"].encode()
                ba = self.alloc_handle("bytearray", size=len(data))
                back = self.bump(len(data))
                mu.mem_write(back, data)
                h[ba]["back"] = back
                return ba
            if mname == "toString":
                src = H(x1)
                data = src.get("data") or "<obj>"
                return self.alloc_handle("string", data=str(data))
            if mname == "toByteArray" and H(x1).get("kind") == "certificate":
                der = H(x1).get("cert") or b""
                ba = self.alloc_handle("bytearray", size=len(der))
                back = self.bump(max(len(der), 1))
                mu.mem_write(back, der)
                h[ba]["back"] = back
                self.calls.append(("jni", "cert.toByteArray", (len(der),)))
                return ba
            if mname == "toByteArray":
                ba = self.alloc_handle("bytearray", size=len(self.cfg["cert"]))
                back = self.bump(len(self.cfg["cert"]))
                mu.mem_write(back, self.cfg["cert"])
                h[ba]["back"] = back
                return ba
            if mname in ("getApkContentsSigners", "getSigningCertificateHistory"):
                arr = self.alloc_handle("objectarray", size=1, elem="signature")
                return arr
            if mname == "getCertificateChain":
                # KeyStore(kp).getCertificateChain: the AndroidKeyStore
                # attestation chain (N certs on a real TEE device, 0 in the
                # old stub).  cfg "attestation_certs": list of DER blobs.
                certs = self.cfg.get("attestation_certs") or []
                arr = self.alloc_handle("objectarray", size=len(certs),
                                        elem="certificate", certs=list(certs))
                return arr
            if mname in ("getMetrics", "getDisplayMetrics"):
                return self.alloc_handle("object", name="DisplayMetrics")
            if mname == "getPackageManager":
                return self.alloc_handle("object", name="PackageManager")
            if mname in ("getPackageInfo",):
                return self.alloc_handle("object", name="PackageInfo")
            if mname == "getContentResolver":
                return self.alloc_handle("object", name="ContentResolver")
            return self.alloc_handle("object", name=mname or "<ret>")
        if nm == "NewObjectV":
            return self.alloc_handle("object", name="<NewObjectV>")
        if nm in ("CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA",
                  "CallIntMethod", "CallIntMethodV", "CallIntMethodA",
                  "CallLongMethod", "CallLongMethodV", "CallLongMethodA"):
            mname = H(x2).get("name")
            if mname == "containsKey":
                # map.containsKey(key): true iff the key holds a non-null value
                # (device-faithful: android_id/fire_adid are absent, not null-
                # valued; the claims rebuild walks ~53 candidate keys)
                key = H(x3)
                kname = key.get("data") if key.get("kind") == "string" else None
                val = self.cfg["strvals"].get(
                    kname, self.cfg["strvals"].get("default")) if kname else None
                self.calls.append(("mapcontains", kname, 1 if val is not None else 0))
                return 1 if val is not None else 0
            if mname == "getSecurityLevel":
                # KeyStore entry security level: device key2 is TEE-generated
                # (sec_level=1); 0 would mean software key
                self.calls.append(("jni", nm, (mname,
                                               self.cfg.get("sec_level", 1))))
                return self.cfg.get("sec_level", 1)
            if mname == "size":
                # SensorManager.getSensorList().size() — anti-emulator probe;
                # a real phone has ~30+ sensors
                self.calls.append(("jni", "sensor_count",
                                   self.cfg.get("sensor_count", 0)))
                return self.cfg.get("sensor_count", 0)
            self.calls.append(("jni", nm, (mname,)))
            return 0
        if nm.startswith("CallVoid") or nm.startswith("CallNonvirtual") or \
           nm in ("ExceptionDescribe", "ExceptionClear", "DeleteLocalRef",
                  "DeleteGlobalRef", "ReleaseStringChars", "ReleaseStringUTFChars",
                  "ReleaseByteArrayElements", "SetObjectArrayElement", "Throw",
                  "SetObjectField", "MonitorEnter", "MonitorExit"):
            return 0
        if nm == "ExceptionCheck" or nm == "ExceptionOccurred":
            return 0
        if nm == "IsSameObject":
            return 0
        if nm == "IsInstanceOf":
            return 1
        if nm in ("NewGlobalRef", "NewLocalRef"):
            return x1
        if nm in ("PushLocalFrame", "EnsureLocalCapacity", "GetVersion", "RegisterNatives",
                  "UnregisterNatives"):
            return 0 if nm != "GetVersion" else 0x10006
        if nm == "PopLocalFrame":
            return x1
        if nm in ("GetSuperclass",):
            return 0
        if nm in ("NewString",):
            self.calls.append(("jni", "NewString", ()))
            return self.alloc_handle("string", data="<newstring>")
        if nm in ("NewStringUTF",):
            try:
                data = cstr(uc, x1)
            except Exception:
                data = None
            self.calls.append(("jni", "NewStringUTF", (data, "0x%x" % x1), "0x%x" % lr))
            return self.alloc_handle("string", data=data if data is not None else "")
        if nm in ("GetStringLength", "GetStringUTFLength"):
            d = H(x1).get("data", "")
            return (len(d) if nm == "GetStringLength" else len(d.encode())) & 0xFFFFFFFF
        if nm == "GetStringUTFChars":
            if x1 == 0:
                self.calls.append(("jni", "GetStringUTFChars", ("<null>",), "0x%x" % lr))
                return 0
            d = H(x1).get("data")
            if d is None:
                d = self.cfg["strvals"].get("default")
            if d is None:
                # null-data string handle: behave like a null jobject
                self.calls.append(("jni", "GetStringUTFChars", ("<nulldata>",), "0x%x" % lr))
                return 0
            b = d.encode() + b"\x00"
            p = self.bump(len(b))
            mu.mem_write(p, b)
            if x2:
                mu.mem_write(x2, struct.pack("<I", 1))
            self.calls.append(("jni", "GetStringUTFChars", (d,)))
            return p
        if nm == "GetStringChars":
            d = H(x1).get("data", "")
            b = d.encode("utf-16-le") + b"\x00\x00"
            p = self.bump(len(b))
            mu.mem_write(p, b)
            return p
        if nm == "GetStringUTFRegion" or nm == "GetStringRegion":
            d = H(x1).get("data", "")
            b = (d.encode() if nm == "GetStringUTFRegion" else d.encode("utf-16-le"))
            mu.mem_write(x3, b[:x2] if False else b)
            return 0
        if nm == "GetArrayLength":
            k = H(x1)
            n = k.get("size", 0)
            self.calls.append(("jni", "GetArrayLength", (k.get("kind"), n)))
            return n & 0xFFFFFFFF
        if nm == "NewByteArray" or nm in ("NewBooleanArray", "NewCharArray", "NewShortArray",
                                          "NewIntArray", "NewLongArray", "NewFloatArray",
                                          "NewDoubleArray"):
            ba = self.alloc_handle("bytearray", size=x1)
            back = self.bump(max(x1, 1))
            h[ba]["back"] = back
            return ba
        if nm == "GetByteArrayElements":
            k = H(x1)
            back = k.get("back")
            if back is None:
                back = self.bump(max(k.get("size", 16), 16))
                h[x1]["back"] = back
            if x2:
                mu.mem_write(x2, struct.pack("<I", 1))
            self.calls.append(("jni", "GetByteArrayElements", (k.get("kind"), k.get("size"))))
            return back
        if nm == "GetByteArrayRegion":
            k = H(x1)
            back = k.get("back")
            start, ln = x2, x3          # JNI: (env, arr, start, len, buf)
            buf = uc.reg_read(UC_ARM64_REG_X4)
            if back is not None and ln:
                n = min(ln, k.get("size", ln) - start)
                mu.mem_write(buf, bytes(mu.mem_read(back + start, max(n, 0))))
            return 0
        if nm == "SetByteArrayRegion":
            k = H(x1)
            back = k.get("back")
            start, ln = x2, x3          # JNI: (env, arr, start, len, buf)
            buf = uc.reg_read(UC_ARM64_REG_X4)
            if back is None:
                back = self.bump(max(ln, 1))
                h[x1]["back"] = back
                k["size"] = max(k.get("size", 0), ln)
            if ln:
                mu.mem_write(back + start, bytes(mu.mem_read(buf, ln)))
            self.calls.append(("jni", "SetByteArrayRegion", (start, ln)))
            return 0
        if nm == "NewObjectArray":
            return self.alloc_handle("objectarray", size=x1, elem="generic")
        if nm == "GetObjectArrayElement":
            k = H(x1)
            el = self.alloc_handle("object", name=k.get("elem", "generic"))
            if k.get("elem") == "signature":
                h[el]["kind"] = "object"
                h[el]["name"] = "Signature"
            if k.get("elem") == "certificate" and "certs" in k:
                idx = k.get("next", 0)
                k["next"] = idx + 1
                h[el]["kind"] = "certificate"
                h[el]["cert"] = k["certs"][min(idx, len(k["certs"]) - 1)] \
                    if k["certs"] else b""
            if k.get("elem") == "stackframe" and "frames" in k:
                idx = k.get("next", 0)
                k["next"] = idx + 1
                fr = k["frames"][min(idx, len(k["frames"]) - 1)] if k["frames"] else ("?", "?")
                h[el]["kind"] = "stackframe"
                h[el]["frame"] = fr
            self.calls.append(("jni", "GetObjectArrayElement", (k.get("kind"),)))
            return el
        if nm == "GetJavaVM":
            mu.mem_write(x1, struct.pack("<Q", self.VM))
            self.calls.append(("jni", "GetJavaVM", (), "0x%x" % lr))
            return 0
        if nm in ("ThrowNew", "Throw"):
            self.calls.append(("jni", nm, (s2,)))
            return 0
        if nm == "FatalError":
            self.stopped = "FatalError(%s)" % s2
            return 0
        if nm == "GetObjectRefType":
            return 1
        self.calls.append(("jni", nm, (x1, x2, x3), "UNHANDLED@0x%x" % lr))
        self.log.append("!! unhandled JNI slot 0x%x %s (lr=0x%x)" % (slot, nm, lr))
        return 0

    # ---------------- driver ----------------
    def run(self, start=0xDB1CC, count=400_000_000, timeout_us=600 * 1_000_000,
            argstyle="nsign"):
        mu = self.mu
        mu.reg_write(UC_ARM64_REG_SP, STACK + 0x100000)
        if argstyle == "nsign":
            # static JNI export: (env, clazz, ctx, map, hmac, sdkInt)
            mu.reg_write(UC_ARM64_REG_X0, self.ENV)
            mu.reg_write(UC_ARM64_REG_X1, self.CLAZZ)
            mu.reg_write(UC_ARM64_REG_X2, self.CTXOBJ)
            mu.reg_write(UC_ARM64_REG_X3, self.MAPOBJ)
            mu.reg_write(UC_ARM64_REG_X4, self.OBJ_HMAC)
            mu.reg_write(UC_ARM64_REG_X5, self.cfg.get("sdk_int", 34))
        else:
            # standalone sub_8d6f4 (legacy shape; VM-internal x0/x3 are unknowable)
            mu.reg_write(UC_ARM64_REG_X0, self.OBJ)
            mu.reg_write(UC_ARM64_REG_X1, self.ENV)
            mu.reg_write(UC_ARM64_REG_X2, self.CTX)
            mu.reg_write(UC_ARM64_REG_X3, self.OBJ_HMAC)
        for r in range(UC_ARM64_REG_X6, UC_ARM64_REG_X18):
            mu.reg_write(r, 0)
        mu.mem_write(STOP, struct.pack("<I", 0xD65F03C0))
        mu.reg_write(UC_ARM64_REG_LR, STOP)
        t0 = pytime.time()
        try:
            mu.emu_start(start, STOP, timeout=timeout_us, count=count)
            self.stopped = self.stopped or ("returned" if
                                            mu.reg_read(UC_ARM64_REG_PC) == STOP else "?")
        except UcError as e:
            self.stopped = "%s pc=0x%x" % (e, mu.reg_read(UC_ARM64_REG_PC))
        self.wall = pytime.time() - t0
        # capture the JNI return value: nSign returns a jbyteArray handle
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        self.result = {"x0": x0, "stopped": self.stopped}
        h = self.handles.get(x0)
        if h:
            self.result["handle"] = {k: v for k, v in h.items() if k != "back"}
            back = h.get("back")
            if back and h.get("kind") == "bytearray" and h.get("size"):
                try:
                    self.result["blob"] = bytes(mu.mem_read(back, h["size"]))
                except UcError:
                    pass
        return self.stopped

    def ctx_bytes(self):
        if self.ctx_seen:
            # last 0xfb64 call's x2
            return bytes(self.mu.mem_read(self.ctx_seen[-1][2], 0x878))
        return bytes(self.mu.mem_read(self.CTX, 0x878))

    def full_mem(self):
        out = {}
        for begin, end, perms in self.mu.mem_regions():
            if end - begin > 0x400000:      # skip huge stack for speed? keep anyway
                pass
            out[begin] = bytes(self.mu.mem_read(begin, min(end - begin + 1, 0x400000)))
        return out

    def find_pattern(self, pat):
        hits = []
        for begin, blob in self.full_mem().items():
            i = blob.find(pat)
            while i >= 0:
                hits.append((begin + i, begin))
                i = blob.find(pat, i + 1)
        return hits


# ---------------------------------------------------------------- reporting
def ctx_wordmap(b):
    return struct.unpack("<%dI" % (len(b) // 4), b)


def diff_ctx(a, b):
    wa, wb = ctx_wordmap(a), ctx_wordmap(b)
    return [(i * 4, wa[i], wb[i]) for i in range(len(wa)) if wa[i] != wb[i]]


def summarize_ctx(b):
    out = []
    for off in range(0, len(b), 4):
        w = struct.unpack_from("<I", b, off)[0]
        if w:
            out.append((off, w))
    return out


PAT8 = struct.pack("<4I", 0xFFFFFFBF, 0x1FFDFFFF, 0x0007, 0)
PAT9_WORDS = (0x0DFAD0F1, 0x173CF960, 0x1E2F7B93, 0x9196C0B6, 0xBD7DAE)
PAT9_LE = b"".join(struct.pack("<I", w) for w in PAT9_WORDS)
PAT9_BE = b"".join(struct.pack(">I", w) for w in PAT9_WORDS)

# sensitivity variations: (name, cfg-override)
def sens_list():
    D = DEF_CFG
    V = [("width 1080->1081", {"width": 1081}),
         ("height 2400->2401", {"height": 2401}),
         ("package other", {"package": "com.other.app"}),
         ("hmac[0]^1", {"hmac": bytes([D["hmac"][0] ^ 1]) + D["hmac"][1:]}),
         ("cert_sha1 vary", {"cert_sha1": bytes((i * 5 + 2) & 0xFF for i in range(20))}),
         ("cert vary", {"cert": bytes((i * 3 + 9) & 0xFF for i in range(1054))}),
         ("sec +1", {"sec": D["sec"] + 1, "time_sec": D["time_sec"] + 1}),
         ("nsec +1ms", {"nsec": D["nsec"] + 1_000_000}),
         ("nsec +1ns", {"nsec": D["nsec"] + 1}),
         ("usec +1", {"usec": D["usec"] + 1}),
         ("tid +1", {"tid": D["tid"] + 1}),
         ("pid +1", {"pid": D["pid"] + 1}),
         ("tls +0x1000", {"tls_base": D["tls_base"] + 0x1000}),
         ("guard ^0xff", {"stack_guard": D["stack_guard"] ^ 0xFF}),
         ("srand 2", {"srand_seed": 2}),
         ("environment val", {"strvals": dict(D["strvals"], environment="sandbox")}),
         ("app_version val", {"strvals": dict(D["strvals"], app_version="3.14.0")}),
         ("android_id non-null", {"strvals": dict(D["strvals"], android_id="9a7c4e2b1d5f8036")}),
         ("client_sdk val", {"strvals": dict(D["strvals"], client_sdk="android5.8.0")}),
         ("secret_id val", {"strvals": dict(D["strvals"], secret_id="other")})]
    for i, p in enumerate(list(D["props"])):
        V.append(("prop[%d]:%s" % (i, p),
                  {"props": dict(D["props"], **{p: "X" + D["props"][p]})}))
    return V


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--sens", action="store_true")
    ap.add_argument("--digest", action="store_true")
    ap.add_argument("--vary", type=str, default=None)
    ap.add_argument("--out", type=str, default=None)
    ap.add_argument("--start", type=lambda s: int(s, 0), default=0xDB1CC,
                    help="0xdb1cc = nSign (full path), 0x8d6f4 = standalone builder (legacy)")
    ap.add_argument("--count", type=int, default=3_000_000_000)
    ap.add_argument("--dump-trace", action="store_true")
    args = ap.parse_args()

    override = json.loads(args.vary) if args.vary else {}
    t_start = args.start
    argstyle = "nsign" if t_start == 0xDB1CC else "vm"

    # ---- baseline / multi-run ----
    runs = []
    for i in range(args.runs):
        e = Emu(cfg=override, digest=args.digest)
        st = e.run(t_start, count=args.count, argstyle=argstyle)
        print("run %d: stopped=%s wall=%.1fs insns=%s relocs=%d calls=%d mrs=%d"
              % (i, st, getattr(e, "wall", 0), e.icount or "?", e.nrel, len(e.calls), len(e.mrs_log)))
        runs.append(e)

    base = runs[0]
    print("\n=== stage summary ===")
    props = [c for c in base.calls if c[0] == "prop"]
    jnis = [c for c in base.calls if c[0] == "jni"]
    vms = [c for c in base.calls if c[0] == "javavm"]
    print("VM->builder calls (0xfb64): %s" % (["ctx=0x%x" % c[2] for c in base.ctx_seen] or "NONE REACHED"))
    print("property probes: %d %s" % (len(props), [p[1] for p in props]))
    print("javavm calls: %s" % vms)
    print("jni calls: %d" % len(jnis))
    for c in jnis:
        print("   ", c[1], c[2])
    clocks = [c for c in base.calls if c[0] in ("clock_gettime", "gettimeofday", "time", "rand")]
    print("time/rand calls:", clocks)
    if base.mrs_log:
        print("mrs reads:", base.mrs_log[:20])

    ctx = base.ctx_bytes()
    nz = summarize_ctx(ctx)
    print("\n=== ctx nonzero words (%d) ===" % len(nz))
    for off, w in nz:
        print("  +0x%03x: %08x" % (off, w))
    h8 = base.find_pattern(PAT8)
    h9 = base.find_pattern(PAT9_LE) + base.find_pattern(PAT9_BE)
    print("#8 anchor pattern hits:", ["0x%x" % a for a, _ in h8])
    print("#9 pattern hits:", ["0x%x" % a for a, _ in h9])
    open(os.path.join(HERE, "emu8_ctx_base.bin"), "wb").write(ctx)

    if args.runs >= 2:
        print("\n=== twice-run verdict ===")
        all_same = True
        for i in range(1, args.runs):
            o = runs[i]
            d = diff_ctx(ctx, o.ctx_bytes())
            same_ctx = not d
            mem_same = base.full_mem() == o.full_mem()
            calls_same = [repr(c) for c in base.calls] == [repr(c) for c in o.calls]
            dig_same = (not args.digest) or base.digest_ckpts == o.digest_ckpts
            print("run%d: ctx_same=%s mem_same=%s calls_same=%s digests_same=%s diff_words=%d"
                  % (i, same_ctx, mem_same, calls_same, dig_same or "n/a", len(d)))
            if not same_ctx:
                all_same = False
                for off, wa, wb in d[:40]:
                    print("    +0x%03x: %08x -> %08x" % (off, wa, wb))
        print("VERDICT:", "IDENTICAL" if all_same else "DIFFERENT")

    if args.sens:
        print("\n=== sensitivity sweep ===")
        results = []
        for name, over in sens_list():
            e = Emu(cfg=over)
            st = e.run(t_start, count=args.count, argstyle=argstyle)
            d = diff_ctx(ctx, e.ctx_bytes())
            offs = sorted(set(o for o, _, _ in d))
            results.append((name, st, offs, d))
            print("%-28s %-40s diff=%2d %s" % (name, str(st)[:40], len(d),
                  " ".join("+0x%x" % o for o in offs[:16])))
            if len(d) > 16:
                print("      ...")
        json.dump([{"name": n, "stopped": s, "diffs": [[o, a, b] for o, a, b in d]}
                   for n, s, offs, d in results],
                  open(os.path.join(HERE, "emu8_sens.json"), "w"), indent=1)

    if args.dump_trace:
        fn = args.out or "emu8_trace.json"
        json.dump({"calls": [list(c) for c in base.calls],
                   "log": base.log,
                   "digest_ckpts": [[a, b] for a, b in base.digest_ckpts]},
                  open(os.path.join(HERE, fn), "w"), indent=1, default=str)
        print("trace dumped to", fn)


if __name__ == "__main__":
    main()
