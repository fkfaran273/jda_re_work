# nsign_addr.py - resolve the JNI entry VA + the likeliest callers, without a symbol
# table: the .dynstr occurrence at 0xf1d + .text scan for the prologue that loads
# it (the JNI registration table holds (name, sig, fnptr) triples - the fnptr is
# a .text VA in the same 64K page as the VM core). Outputs candidates for dump_fn.py
import re
import struct
import sys

SO = (r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a"
      r"\libsigner.so")
d = open(SO, "rb").read()
STR = 0xF1D

# 1. .text range: biggest RX-looking region is found by scanning for the classic
# prologue density; simpler: take the file's largest code-looking chunk via the
# program headers.
phoff, = struct.unpack_from("<Q", d, 0x20)
phentsize, phnum = struct.unpack_from("<HH", d, 0x36)
print("phoff=%s entsize=%s num=%s" % (hex(phoff), phentsize, phnum))
for i in range(phnum):
    row = struct.unpack_from("<IIQQQQQQ", d, phoff + i * phentsize)
    print("  LOAD" if row[0] == 1 else "  other", ["%x" % x for x in row[1:]])
text = None
for i in range(phnum):
    p_type, p_flags, p_off, p_v, p_p, p_fs, p_ms, p_al = struct.unpack_from(
        "<IIQQQQQQ", d, phoff + i * phentsize)
    if p_type == 1 and (p_flags & 1) and (p_flags & 4) and p_fs > (text[2] if text else 0):
        text = (p_off, p_v, p_fs)
print("text: file=%s vaddr=%s size=%s" % tuple(hex(x) for x in text))
toff, tv, tsz = text

# 2. candidate JNI registration table: pointer pairs in +-2MB of typical table data
# referencing an 8-byte aligned vaddr inside .text and sitting at file alignment.
cands = []
step = 8
code = d[toff:toff + tsz]
for base in range(0, tsz - 16, step):
    a = struct.unpack_from("<Q", code, base)[0]
    b = struct.unpack_from("<Q", code, base + 8)[0]
    if tv <= a < tv + tsz and (a & 3) == 0:
        cands.append((tv + base, a, b))
print("text-internal qword pairs: %d (registration-table shaped)" % len(cands))

# 3. dynamic string table mirror: count NUL-terminated 'Java_com...' entries and the
#    3-qword (name,sig,fn) windows that usually follow JNI_OnLoad tables in .rodata
names = [m.start() for m in re.finditer(rb"Java_com_adjust_sdk_sig_\w+", d)]
print("Java_com_adjust_sdk_sig_* strings at:", [hex(x) for x in names])
for n in names:
    for w in range(0, 48, 8):
        if n + w + 24 > len(d):
            break
        q = struct.unpack_from("<QQQ", d, n + w)
        if any(tv <= x < tv + tsz and (x & 3) == 0 for x in q):
            print("  near+%d: %s -> points into .text" % (w, [hex(x) for x in q]))