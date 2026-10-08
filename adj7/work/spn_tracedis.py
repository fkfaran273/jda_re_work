"""spn_tracedis.py — disassemble the v5 instruction trace, find memcpy/memset
call sites (bl to 0xd0000xxx) and their register context; build the dataflow
around the chunk-15 output buffer.

    python spn_tracedis.py [start_line] [end_line]
"""
import os
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work", "bins",
                                  "adjust-android-signature-3.62", "jni",
                                  "arm64-v8a", "libsigner.so"))
data = open(SO, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

PLT = {0xd0000000 + i * 8: nm for i, nm in enumerate(
    "__cxa_finalize __cxa_atexit free __stack_chk_fail memset calloc sscanf "
    "strdup fgets fclose memcpy clock_gettime strtol strchr strcmp strncmp "
    "fstat mmap munmap __system_property_get access vsnprintf timer_create "
    "timer_settime read close __strlen_chk realloc opendir readlink readdir "
    "closedir __errno stat rand time srand malloc strlen syscall fopen fread "
    "fseek ftell fmod localtime strftime gettimeofday getpid fputs "
    "__android_log_print __memcpy_chk sendto recvfrom inet_aton socket "
    "setsockopt connect write getauxval".split())}

start = int(sys.argv[1]) if len(sys.argv) > 1 else 0
end = int(sys.argv[2]) if len(sys.argv) > 2 else 200000

rows = []
with open(os.path.join(HERE, "v5_codetrace.txt")) as f:
    for i, ln in enumerate(f):
        if i < start:
            continue
        if i >= end:
            break
        p = ln.split()
        rows.append((int(p[0], 16), [int(x, 16) for x in p[1:]]))
print("rows", len(rows))

# disasm cache
cache = {}
def dis(pc):
    if pc not in cache:
        v = pc - 0x400000
        try:
            ins = next(md.disasm(data[v:v + 4], pc))
            cache[pc] = "%s %s" % (ins.mnemonic, ins.op_str)
        except StopIteration:
            cache[pc] = "?"
    return cache[pc]

# find bl-to-plt
hits = []
for i, (pc, regs) in enumerate(rows):
    d = dis(pc)
    if d.startswith("bl ") or d.startswith("b "):
        try:
            tgt = int(d.split()[1], 16)
        except ValueError:
            continue
        if tgt in PLT:
            hits.append((i, pc, PLT[tgt], regs))
print("plt calls:", len(hits))
from collections import Counter
print(Counter(h[2] for h in hits).most_common(10))
for i, pc, nm, regs in hits[:40]:
    print("line %d pc=%x %s x0=%x x1=%x x2=%x x3=%x" %
          (i + start, pc, nm, regs[0], regs[1], regs[2], regs[3]))
