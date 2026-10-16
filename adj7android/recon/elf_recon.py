# Fresh recon of libsigner.so — pure stdlib ELF parser + symbol/string dump
import struct, sys, re

PATH = sys.argv[1] if len(sys.argv) > 1 else r"..\apks\lib\hanaf\libsigner.so"
d = open(PATH, "rb").read()
print("size", len(d))

assert d[:4] == b"\x7fELF"
is64 = d[4] == 2
(e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
    struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
print("machine", e_machine, "type", e_type, "entry", hex(e_entry))

secs = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
     sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from("<IIQQQQIIQQ", d, off)
    secs.append(dict(name_off=sh_name, type=sh_type, addr=sh_addr, off=sh_offset,
                     size=sh_size, link=sh_link, entsize=sh_entsize))
shstr = secs[e_shstrndx]
def cstr(buf, o):
    e = buf.index(b"\0", o)
    return buf[o:e].decode()
for s in secs:
    s["name"] = cstr(d[shstr["off"]:shstr["off"] + shstr["size"]], s["name_off"])
print("\n== sections ==")
for s in secs:
    print("  %-20s addr=%012x off=%08x size=%08x type=%d" %
          (s["name"], s["addr"], s["off"], s["size"], s["type"]))

def addr2off(a):
    for s in secs:
        if s["type"] != 8 and s["addr"] and s["addr"] <= a < s["addr"] + s["size"]:
            return s["off"] + (a - s["addr"])
    return None

# dynamic symbols via .dynsym/.dynstr
dyn = next((s for s in secs if s["name"] == ".dynsym"), None)
dstr = next((s for s in secs if s["name"] == ".dynstr"), None)
if dyn and dstr:
    strtab = d[dstr["off"]:dstr["off"] + dstr["size"]]
    print("\n== dynsyms (%d) ==" % (dyn["size"] // dyn["entsize"]))
    exp, imp = [], []
    for i in range(dyn["size"] // dyn["entsize"]):
        o = dyn["off"] + i * dyn["entsize"]
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", d, o)
        nm = cstr(strtab, st_name)
        if not nm:
            continue
        bind = st_info >> 4
        typ = st_info & 0xF
        if st_shndx == 0:
            imp.append(nm)
        elif st_value:
            exp.append((nm, st_value, st_size, typ))
    print("-- undefined imports:", len(imp))
    for nm in imp:
        print("   U", nm)
    print("-- defined exports:", len(exp))
    for nm, v, sz, t in sorted(exp, key=lambda x: x[1]):
        print("   %012x %6x t%d  %s" % (v, sz, t, nm))

# interesting strings
print("\n== strings ==")
for m in re.finditer(rb"[\x20-\x7e]{4,}", d):
    s = m.group().decode()
    if re.search(r"(?i)sign|adj|version|3\.6|jni|java/|aes|hmac|sha|rand|seed|claim|cert|nonce|activity|sdk", s):
        print("   @%08x %s" % (m.start(), s[:120]))
