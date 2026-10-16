# Fresh unicorn harness for the 3.62.0 adj7 libsigner.so (payruki/hunch/mitra apps).
# Modeled on the proven adj8 harness layout (headers_id arg, containsKey/get map
# access, VFS-backed APK read) but rewritten for this native.
import struct, sys, os
from unicorn import *
from unicorn.arm64_const import *

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "..", "apks", "lib", "hanaf", "libsigner.so")
BASE = 0x400000
STACK, STACK_SZ = 0x7000000, 0x200000
HEAP, HEAP_SZ = 0x9000000, 0x800000
ENV_TABLE = 0xB000000
MAGIC_BASE = 0xE0000000          # JNI slot trampolines
FAKE_PLT = 0xD0000000            # import trampolines
NSIGN = 0xa95ac
NONRESUME = 0xa894c
HEADERS_ID = 8

data = open(SO, "rb").read()

e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr = struct.unpack_from("<IIQQ", data, off)
    p_filesz, p_memsz = struct.unpack_from("<QQ", data, off + 32)
    if p_type == 1:
        segs.append((p_offset, p_vaddr, p_filesz, p_memsz))

e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
secs = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    nm, typ = struct.unpack_from("<II", data, off)
    addr, offset, size = struct.unpack_from("<QQQ", data, off + 16)
    secs.append(dict(name=nm, addr=addr, offset=offset, size=size))
shstr = secs[e_shstrndx]
def sname(n):
    end = data.index(b"\x00", shstr["offset"] + n)
    return data[shstr["offset"] + n:end].decode()
byname = {sname(s["name"]): s for s in secs}
dynsym, dynstr = byname[".dynsym"], byname[".dynstr"]
def sym_name(idx):
    off = dynsym["offset"] + idx * 24
    st_name = struct.unpack_from("<I", data, off)[0]
    end = data.index(b"\x00", dynstr["offset"] + st_name)
    return data[dynstr["offset"] + st_name:end].decode()

plt_map, got_map = {}, {}
rel = byname[".rela.plt"]
for i in range(rel["size"] // 24):
    off = rel["offset"] + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
    if (r_info & 0xFFFFFFFF) in (1025, 1026):
        plt_map[r_offset] = sym_name(r_info >> 32)
rel = byname[".rela.dyn"]
for i in range(rel["size"] // 24):
    off = rel["offset"] + i * 24
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
    t = r_info & 0xFFFFFFFF
    if t == 1027:
        got_map[r_offset] = ("REL", r_addend)
    elif t in (1025, 1026):
        got_map[r_offset] = sym_name(r_info >> 32)
plt_names = list(plt_map.items())
plt_addr = {nm: FAKE_PLT + i * 8 for i, (got, nm) in enumerate(plt_names)}


class Random3Bionic:
    """bionic rand(): 31-word additive LCG (Schrage MINSTD seeding), 310
    warm-up draws, output = word >> 1."""
    M = (1 << 31) - 1
    A = 16807
    Q = M // A
    R = M % A

    def __init__(self, seed):
        s = seed & 0xFFFFFFFF
        if s == 0:
            s = 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        self.r = [0] * 31
        self.r[0] = w
        prev = w
        for i in range(1, 31):
            if prev >= 0:
                hi, lo = divmod(prev, self.Q)
            else:
                hi = -((-prev) // self.Q)
                lo = prev - hi * self.Q
            word = self.A * lo - self.R * hi
            if word < 0:
                word += self.M
            prev = word
            self.r[i] = word
        self.f, self.b = 3, 0
        for _ in range(310):
            self.next()

    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o


class Obj:
    def __init__(self, kind, val=None):
        self.kind = kind
        self.val = val
        self.fields = {}


class Emu:
    def __init__(self, verbose=False, apk_path=None, package=None, cert=None):
        self.verbose = verbose
        self.jni_log = []
        self.map_reads = []
        self.output = None
        self.pcring = []
        self.hook_count = 0
        self.freelist = []
        self.sizes = {}
        self.elem_map = {}
        self.package = package or "in.hanafintech"
        self.apk_bytes = open(apk_path, "rb").read() if apk_path else open(
            os.path.join(HERE, "..", "apks", "hanaf_base.apk"), "rb").read()
        self.fixed_time = 1789373822
        self.clock_nsec = 0
        self.nonce12 = None
        self.srand_seeds = []
        self.rand_calls = 0
        self.records = []
        self.schedules = []
        self._init2()

    def _init2(self):
        uc = self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.vfs = {"/data/app/base.apk": self.apk_bytes}
        self.vfs_open = {}
        self.rng = Random3Bionic(1)
        for off, vaddr, filesz, memsz in segs:
            start = BASE + (vaddr & ~0xFFF)
            end = (BASE + vaddr + memsz + 0xFFF) & ~0xFFF
            try:
                uc.mem_map(start, end - start)
            except UcError:
                pass
            uc.mem_write(BASE + vaddr, data[off:off + filesz])
        uc.mem_map(STACK, STACK_SZ)
        uc.mem_map(HEAP, HEAP_SZ)
        self.brk = HEAP + 0x1000
        uc.mem_map(ENV_TABLE, 0x2000)
        uc.mem_map(MAGIC_BASE, 0x100000)
        uc.mem_map(FAKE_PLT, 0x10000)
        self.env_ptr = 0x5000000
        uc.mem_map(self.env_ptr, 0x1000)
        uc.mem_write(self.env_ptr, struct.pack("<Q", ENV_TABLE))
        self.tls = 0x6000000
        uc.mem_map(self.tls, 0x1000)
        uc.mem_write(self.tls + 0x28, bytes(8))
        self.heap_objs = {}
        # resolve GOT slots for PLT stubs
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        pltsec = byname[".plt"]
        for i, (got, nm) in enumerate(plt_names):
            stub = pltsec["addr"] + 32 + i * 16
            code = data[pltsec["offset"] + 32 + i * 16:
                        pltsec["offset"] + 32 + i * 16 + 16]
            gotaddr, page = None, 0
            for ins in md.disasm(code, stub):
                if ins.mnemonic == "adrp":
                    page = int(ins.op_str.split("#")[1], 16)
                elif ins.mnemonic == "ldr":
                    op = ins.op_str
                    gotaddr = page + (int(op.split("#")[1].rstrip("]"), 16)
                                      if "#" in op else 0)
                    break
            if gotaddr is None:
                gotaddr = BASE + got
            else:
                gotaddr = BASE + gotaddr
            try:
                uc.mem_write(gotaddr, struct.pack("<Q", plt_addr[nm]))
            except UcError:
                pass
        for got, val in got_map.items():
            if isinstance(val, tuple):
                uc.mem_write(BASE + got, struct.pack("<Q", BASE + val[1]))
            elif val in plt_addr:
                uc.mem_write(BASE + got, struct.pack("<Q", plt_addr[val]))
        for i in range(256):
            uc.mem_write(ENV_TABLE + 8 * i,
                         struct.pack("<Q", MAGIC_BASE + i * 8))
        uc.hook_add(UC_HOOK_CODE, self.hook_code, begin=MAGIC_BASE,
                    end=MAGIC_BASE + 0xFFFFF)
        uc.hook_add(UC_HOOK_CODE, self.hook_code, begin=FAKE_PLT,
                    end=FAKE_PLT + 0xFFFF)
        uc.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
        uc.reg_write(UC_ARM64_REG_TPIDR_EL0, self.tls)

    def hook_mem_invalid(self, uc, access, address, size, value, user):
        print("INVALID MEM %#x access=%d size=%d pc=%#x"
              % (address, access, size, uc.reg_read(UC_ARM64_REG_PC)))
        print("pcs:", [hex(p) for p in self.pcring[-10:]])
        return False

    def alloc(self, size, fill=None):
        size = max(int(size), 1)
        need = (size + 31) & ~15
        for i, (p0, n0) in enumerate(self.freelist):
            if n0 >= need:
                del self.freelist[i]
                self.sizes[p0] = n0
                if fill is not None:
                    uc = self.uc
                    uc.mem_write(p0, bytes(fill))
                return p0
        p = self.brk
        self.brk += need
        self.sizes[p] = need
        if fill is not None:
            self.uc.mem_write(p, bytes(fill))
        return p

    def newobj(self, kind, val=None):
        ref = 0x30000000 + len(self.heap_objs) * 8 + 0x100
        self.heap_objs[ref] = Obj(kind, val)
        return ref

    def jstr(self, ref):
        o = self.heap_objs.get(ref)
        if o is None:
            return None
        return o.val if isinstance(o.val, (bytes, bytearray)) else None

    def read_cstr(self, p):
        b = b""
        while p and len(b) < 65536:
            c = bytes(self.uc.mem_read(p + len(b), 1))
            if c == b"\x00":
                break
            b += c
        return b

    def hook_code(self, uc, address, size, user):
        self.hook_count += 1
        self.pcring.append(address)
        if len(self.pcring) > 40:
            self.pcring.pop(0)
        if MAGIC_BASE <= address < MAGIC_BASE + 0x100000:
            self.jni_dispatch(uc, (address - MAGIC_BASE) // 8)
        else:
            self.plt_dispatch(uc, plt_names[(address - FAKE_PLT) // 8][1])

    # ---------------------------------------------------------------- libc
    def plt_dispatch(self, uc, name):
        ret = uc.reg_read(UC_ARM64_REG_LR)
        X = UC_ARM64_REG_X0
        a = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                      UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                      UC_ARM64_REG_X4)]
        if self.verbose:
            extra = ""
            if name in ("fopen", "opendir", "open", "access") and a[0]:
                extra = self.read_cstr(a[0]).decode("latin1", "replace")
            print("PLT", name, [hex(x) for x in a[:3]], extra)
        if name in ("calloc", "malloc"):
            n = a[0] * (a[1] or 1) if name == "calloc" else a[0]
            p = self.alloc(max(n, 1))
            if name == "calloc":
                uc.mem_write(p, bytes(min(max(n, 1), 1 << 22)))
            uc.reg_write(X, p)
        elif name == "realloc":
            old, newsz = a[0], max(a[1], 64)
            p = self.alloc(newsz)
            if old and old in self.sizes:
                keep = min(self.sizes[old], newsz)
                if keep > 0:
                    uc.mem_write(p, bytes(uc.mem_read(old, keep)))
                self.freelist.append((old, self.sizes.pop(old)))
            uc.reg_write(X, p)
        elif name == "free":
            n0 = self.sizes.pop(a[0], 0)
            if n0:
                self.freelist.append((a[0], n0))
            uc.reg_write(X, 0)
        elif name in ("memcpy", "__memcpy_chk", "memmove"):
            d, s_, n = a[0], a[1], a[2]
            if 0 < n < (1 << 22):
                uc.mem_write(d, bytes(uc.mem_read(s_, n)))
            uc.reg_write(X, d)
        elif name == "memset":
            d, c, n = a[0], a[1], a[2]
            if 0 < n < (1 << 22):
                uc.mem_write(d, bytes([c & 0xFF]) * n)
            uc.reg_write(X, d)
        elif name in ("strlen", "__strlen_chk"):
            p, n = a[0], 0
            while p and bytes(uc.mem_read(p + n, 1)) != b"\x00" and n < 65536:
                n += 1
            uc.reg_write(X, n)
        elif name == "strcmp":
            b1 = bytes(uc.mem_read(a[0], 4096)).split(b"\x00")[0]
            b2 = bytes(uc.mem_read(a[1], 4096)).split(b"\x00")[0]
            uc.reg_write(X, 0 if b1 == b2 else (1 if b1 > b2 else 0xFFFFFFFFFFFFFFFF))
        elif name == "strncmp":
            n = min(a[2], 4096)
            b1 = bytes(uc.mem_read(a[0], n))
            b2 = bytes(uc.mem_read(a[1], n))
            uc.reg_write(X, 0 if b1 == b2 else 1)
        elif name == "strchr":
            b = bytes(uc.mem_read(a[1], 1))
            s_ = bytes(uc.mem_read(a[0], 4096))
            i = s_.find(b)
            uc.reg_write(X, a[0] + i if i >= 0 else 0)
        elif name == "strdup":
            b = bytes(uc.mem_read(a[0], 4096)).split(b"\x00")[0]
            uc.reg_write(X, self.alloc(len(b) + 1, b + b"\x00"))
        elif name == "clock_gettime":
            uc.mem_write(a[1], struct.pack("<qq", self.fixed_time,
                                           self.clock_nsec))
            uc.reg_write(X, 0)
        elif name == "srand":
            self.srand_seeds.append(a[0] & 0xFFFFFFFF)
            self.rng = Random3Bionic(a[0] & 0xFFFFFFFF)
            uc.reg_write(X, 0)
        elif name in ("rand", "random"):
            self.rand_calls += 1
            uc.reg_write(X, self.rng.next())
        elif name == "time":
            if a[0]:
                uc.mem_write(a[0], struct.pack("<q", self.fixed_time))
            uc.reg_write(X, self.fixed_time)
        elif name == "gettimeofday":
            uc.mem_write(a[0], struct.pack("<qq", self.fixed_time,
                                           self.clock_nsec))
            uc.reg_write(X, 0)
        elif name == "sscanf":
            uc.reg_write(X, 0)
        elif name == "mmap":
            uc.reg_write(X, self.alloc(max(a[1], 0x1000)))
        elif name == "syscall":
            uc.reg_write(X, 12345 if a[0] != 98 else 0)
        elif name in ("socket", "connect", "sendto", "recvfrom", "inet_aton"):
            uc.reg_write(X, 0xFFFFFFFFFFFFFFFF)
        elif name == "fopen":
            path = self.read_cstr(a[0]).decode("latin1", "replace")
            content = self.vfs.get(path)
            if content is None:
                uc.reg_write(X, 0)
            else:
                fh = 0xF1000000 + len(self.vfs_open) * 8 + 8
                self.vfs_open[fh] = [content, 0]
                uc.reg_write(X, fh)
        elif name == "fread":
            fh = a[4]
            entry = self.vfs_open.get(fh)
            if entry is None:
                uc.reg_write(X, 0)
            else:
                content, pos = entry
                sz = a[0] * a[1] if a[0] and a[1] else a[1]
                chunk = content[pos:pos + sz]
                uc.mem_write(a[3], chunk)
                entry[1] += len(chunk)
                uc.reg_write(X, len(chunk) // max(a[1], 1) if a[1] else len(chunk))
        elif name in ("read", "pread"):
            fh = a[0]
            if fh in self.vfs_open:
                content, pos = self.vfs_open[fh]
                chunk = content[pos:pos + a[2]]
                uc.mem_write(a[1], chunk)
                self.vfs_open[fh][1] += len(chunk)
                uc.reg_write(X, len(chunk))
            elif self.nonce12 is not None:
                uc.mem_write(a[1], self._urandom(a[2]))
                uc.reg_write(X, a[2])
            else:
                uc.reg_write(X, a[2])
        elif name == "fseek":
            fh, off, whence = a[0], a[1], a[2]
            if fh in self.vfs_open:
                c, p = self.vfs_open[fh]
                if whence == 0:
                    self.vfs_open[fh][1] = off
                elif whence == 1:
                    self.vfs_open[fh][1] = p + off
                else:
                    self.vfs_open[fh][1] = len(c) + off
            uc.reg_write(X, 0)
        elif name == "ftell":
            uc.reg_write(X, self.vfs_open[a[0]][1] if a[0] in self.vfs_open else 0)
        elif name == "fstat":
            fh = a[0]
            if fh in self.vfs_open:
                uc.mem_write(a[1] + 48, struct.pack("<Q", len(self.vfs_open[fh][0])))
                uc.reg_write(X, 0)
            else:
                uc.reg_write(X, 0xFFFFFFFFFFFFFFFF)
        elif name == "opendir":
            uc.reg_write(X, 0)
        elif name in ("readdir", "closedir"):
            uc.reg_write(X, 0)
        elif name == "__system_property_get":
            nm = self.read_cstr(a[0]).decode("latin1", "replace")
            if a[1]:
                uc.mem_write(a[1], b"\x00")
            uc.reg_write(X, 0)
            if self.verbose:
                print("  prop", nm, "-> ''")
        elif name == "vsnprintf":
            uc.reg_write(X, 0)
        elif name == "__stack_chk_fail":
            print("STACK CHK FAIL")
            uc.emu_stop()
        elif name in ("getauxval",):
            uc.reg_write(X, 0xFF if a[0] == 16 else 0)
        elif name == "getpid":
            uc.reg_write(X, 12345)
        else:
            uc.reg_write(X, 0)
        uc.reg_write(UC_ARM64_REG_PC, ret)

    def _urandom(self, n):
        if not self.nonce12:
            import os as _os
            return _os.urandom(n)
        src = bytes(self.nonce12)
        out = bytearray()
        while len(out) < n:
            out += src
        r = bytes(out[:n])
        return r

    # ---------------------------------------------------------------- JNI
    def jni_dispatch(self, uc, idx):
        ret = uc.reg_read(UC_ARM64_REG_LR)
        x = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                      UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                      UC_ARM64_REG_X4)]
        out = self.jni_call(uc, idx, x)
        if out is not None:
            uc.reg_write(UC_ARM64_REG_X0, out)
        uc.reg_write(UC_ARM64_REG_PC, ret)

    def jni_call(self, uc, idx, x):
        v = self.verbose
        o = self.heap_objs
        NAME = {6: "FindClass", 31: "GetObjectClass", 33: "GetMethodID",
                34: "CallObjectMethod", 49: "CallBooleanMethod",
                58: "CallIntMethod", 66: "CallVoidMethod",
                94: "GetFieldID", 95: "GetObjectField",
                113: "GetStaticMethodID", 114: "CallStaticObjectMethod",
                167: "NewStringUTF", 168: "GetStringUTFLength",
                169: "GetStringUTFChars", 170: "ReleaseStringUTFChars",
                171: "GetArrayLength", 173: "GetObjectArrayElement",
                176: "NewByteArray", 184: "GetByteArrayElements",
                192: "ReleaseByteArrayElements", 200: "GetByteArrayRegion",
                208: "SetByteArrayRegion", 222: "GetPrimitiveArrayCritical",
                223: "ReleasePrimitiveArrayCritical", 219: "GetJavaVM"}
        nm = NAME.get(idx, "jni%d" % idx)
        if nm not in ("ReleaseStringUTFChars", "ReleaseByteArrayElements"):
            self.jni_log.append((idx, nm))
        if v and idx not in (169, 170, 192):
            print("JNI", idx, nm, hex(x[1]), o.get(x[1]) and o[x[1]].kind)
        if idx == 192 or idx == 223:        # ReleaseByteArrayElements
            p = x[1]
            arr_ref = self.elem_map.pop(p, None)
            if arr_ref:
                tgt = o.get(arr_ref)
                if tgt and tgt.val is not None:
                    tgt.val[:] = bytes(uc.mem_read(p, len(tgt.val)))
            return 0
        if idx in (15, 17, 23, 25, 219, 170, 24, 232):
            return 0
        if idx == 31:
            return x[1]
        if idx == 6:
            cn = self.read_cstr(x[1])
            if v:
                print("FindClass", cn)
            return self.newobj("class", cn)
        if idx in (33, 113):
            return self.newobj("method", (self.read_cstr(x[2]),
                                          self.read_cstr(x[3])))
        if idx == 94:
            fname = self.read_cstr(x[2])
            if v:
                print("GetFieldID", fname)
            return self.newobj("field", fname)
        if idx == 95:
            obj = o.get(x[1])
            fn = o.get(x[2])
            key = fn.val if fn else "?"
            val = obj.fields.get(key) if obj else None
            if isinstance(val, int):
                return val
            return self.newobj("string", str(val).encode())
        if idx in (34, 49, 58, 66, 114, 144) or 35 <= idx <= 66 \
                or 115 <= idx <= 146:
            m = o.get(x[2])
            mname = m.val[0] if m else "static%d" % idx
            return self.call_method(x, mname)
        if idx == 167:
            return self.newobj("string", self.read_cstr(x[1]))
        if idx == 169:
            b = self.jstr(x[1]) or b""
            return self.alloc(len(b) + 1, b + b"\x00")
        if idx == 168:
            return len(self.jstr(x[1]) or b"")
        if idx == 171:
            arr = o.get(x[1])
            return len(arr.val) if arr and arr.val is not None else 0
        if idx in (184, 222):
            arr = o.get(x[1])
            b = bytes(arr.val) if arr and arr.val else b""
            p = self.alloc(max(len(b), 1), b)
            self.elem_map[p] = x[1]
            return p
        if idx == 173:
            arr = o.get(x[1])
            if arr and isinstance(arr.val, list):
                return arr.val[x[2]] if x[2] < len(arr.val) else 0
            return 0
        if idx == 176:
            return self.newobj("bytearray", bytearray(max(x[1], 0)))
        if idx == 200:
            arr = o.get(x[1])
            b = bytes(arr.val) if arr and arr.val else b""
            ln = min(x[3], len(b))
            if ln > 0:
                uc.mem_write(x[2], b[:ln])
            return 0
        if idx == 208:
            arr = o.get(x[1])
            start, ln, buf = x[2], x[3], x[4]
            if arr and arr.val is not None and 0 < ln < (1 << 22):
                need = start + ln
                if len(arr.val) < need:
                    arr.val.extend(bytes(need - len(arr.val)))
                arr.val[start:start + ln] = bytes(uc.mem_read(buf, ln))
                self.output = bytes(arr.val)
                print("SET BYTE ARRAY REGION len=%d off=%d" % (ln, start))
            return 0
        if v:
            print("UNIMPL JNI", idx, nm)
        return 0

    def call_method(self, x, mname):
        uc = self.uc
        o = self.heap_objs
        obj = o.get(x[1])
        kind = obj.kind if obj else "?"
        mname = mname.decode("latin1") if isinstance(mname, bytes) else mname
        self.jni_log.append(("call", kind, mname))
        if self.verbose:
            print("CALL", kind, mname, [hex(t) for t in x[3:5]])
        if kind == "map":
            if mname == "containsKey":
                key = self.jstr(x[3])
                k = key.decode("latin1") if key else ""
                self.map_reads.append("?" + k)
                return 1 if (obj.val or {}).get(k) is not None else 0
            if mname == "get":
                key = self.jstr(x[3])
                k = key.decode("latin1") if key else ""
                self.map_reads.append(k)
                val = (obj.val or {}).get(k)
                if val is None:
                    return 0
                return self.newobj("string", str(val).encode())
            if mname == "size":
                return len(obj.val or {})
            return 0
        if kind == "context":
            if mname == "getPackageName":
                return self.newobj("string", self.package.encode())
            if mname == "getPackageManager":
                pm = obj.val.get("pm")
                if pm is None:
                    pm = self.newobj("pkgmgr", {})
                    obj.val["pm"] = pm
                return pm
            if mname == "getApplicationContext":
                return x[1]
            if mname == "getSystemService":
                return self.newobj("service", mname)
            return self.newobj("service", mname)
        if kind in ("pkgmgr", "service"):
            if mname == "getPackageInfo":
                pi_ref = self.newobj("pkginfo", {})
                pi = self.heap_objs[pi_ref]
                sigarr = self.newobj("sigarray", [])
                pi.fields["signatures"] = sigarr
                pi.fields["applicationInfo"] = self._appinfo()
                return pi_ref
            if mname == "getApplicationInfo":
                return self._appinfo()
            return 0
        if kind == "appinfo":
            return 0
        if kind == "signature":
            if mname == "toByteArray":
                return self.newobj("bytearray", bytearray(obj.val))
            return 0
        return 0

    def _appinfo(self):
        ai = self.newobj("appinfo", {})
        a = self.heap_objs[ai]
        src = self.newobj("string", b"/data/app/base.apk")
        a.fields["sourceDir"] = src
        a.fields["publicSourceDir"] = src
        a.fields["dataDir"] = self.newobj("string",
                                          ("/data/data/" + self.package).encode())
        a.fields["nativeLibraryDir"] = self.newobj("string", b"/data/lib")
        return ai

    # ---------------------------------------------------------------- run
    def run(self, payload, mapobj, second=None, headers_id=HEADERS_ID,
            on_resume=True):
        uc = self.uc
        if second is not None:
            self.fixed_time = int(second)
        sp = STACK + STACK_SZ - 0x10000
        payref = self.newobj("bytearray", bytearray(payload))
        mapref = self.newobj("map", dict(mapobj))
        ctxref = self.newobj("context", {})
        if on_resume:
            uc.reg_write(UC_ARM64_REG_SP, sp)
            uc.reg_write(UC_ARM64_REG_X0, self.env_ptr)
            uc.reg_write(UC_ARM64_REG_X1, 0x1234)
            uc.reg_write(UC_ARM64_REG_LR, 0xDEAD0000)
            try:
                uc.emu_start(BASE + NONRESUME, 0xDEAD0000,
                             timeout=30 * 1000000)
            except UcError as e:
                print("nOnResume err:", e)
        uc.reg_write(UC_ARM64_REG_SP, sp)
        uc.reg_write(UC_ARM64_REG_X0, self.env_ptr)
        uc.reg_write(UC_ARM64_REG_X1, 0x1234)
        uc.reg_write(UC_ARM64_REG_X2, ctxref)
        uc.reg_write(UC_ARM64_REG_X3, mapref)
        uc.reg_write(UC_ARM64_REG_X4, payref)
        uc.reg_write(UC_ARM64_REG_X5, headers_id)
        uc.reg_write(UC_ARM64_REG_LR, 0xDEAD0000)
        try:
            uc.emu_start(BASE + NSIGN, 0xDEAD0000, timeout=600 * 1000000)
        except UcError as e:
            print("UC ERR:", e, "pc=%#x" % uc.reg_read(UC_ARM64_REG_PC))
            print("pcs:", [hex(p) for p in self.pcring[-14:]])
            print("jni tail:", self.jni_log[-24:])
            return None
        for p, ref in self.elem_map.items():
            tgt = self.heap_objs.get(ref)
            if tgt and tgt.val is not None:
                try:
                    tgt.val[:] = bytes(uc.mem_read(p, len(tgt.val)))
                except UcError:
                    pass
        out_ref = uc.reg_read(UC_ARM64_REG_X0)
        o = self.heap_objs.get(out_ref)
        if o and o.kind == "bytearray":
            self.output = bytes(o.val)
            return self.output
        print("returned non-bytearray:", hex(out_ref), o and o.kind)
        return None


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", default='{"app_token":"smxi7gqwu39c","package_name":"in.hanafintech","activity_kind":"session","client_sdk":"android5.6.0"}')
    ap.add_argument("--second", type=int, default=None)
    ap.add_argument("--nonce", default=None)
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("-v", action="store_true")
    A = ap.parse_args()
    e = Emu(verbose=A.v)
    if A.nonce:
        e.nonce12 = bytes.fromhex(A.nonce)
    out = e.run(payload=bytes(32), mapobj=json.loads(A.params),
                second=A.second, on_resume=not A.no_resume)
    if out:
        print("blob(%d): %s" % (len(out), out.hex().upper()))
    print("srand:", e.srand_seeds, "rand calls:", e.rand_calls)
    print("map reads:", e.map_reads[:50])
