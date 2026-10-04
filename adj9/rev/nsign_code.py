# nsign_code.py - which FUNCTIONS reference the JNI name strings / .data.rel.ro
# pointers / OBFUSCATOR_TAG, using the repo's own datarefs map.
#
# Outputs candidate code VAs to feed to dump_fn.py, so the descriptor-construction
# (region #0/#2/#4) site can be located: the nSign body that fills the va table.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import datarefs as D

e, refs, by_data, strs, funcs = D.build()
text = e.byname[".text"]
print(".text va=%s size=%s" % (hex(text["addr"]), hex(text["size"])))


def show_data(va, why):
    cs = sorted(set(by_data.get(va, [])))
    hits = [D.func_of(funcs, c) for c in cs]
    fns = sorted(set(h for h in hits if h is not None))
    print("data %s (%s): %d code refs -> funcs %s"
          % (hex(va), why, len(cs), [hex(f) for f in fns[:12]]))
    for c in cs[:8]:
        print("   ref@%s func=%s" % (hex(c), hex(D.func_of(funcs, c))))


# 1. the JNI name-string VAs: strings dict only covers .data*; resolve via segment
d = e.data
for want, tag in ((b"Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume", "nOnResume"),
                  (b"Java_com_adjust_sdk_sig_NativeLibHelper_nSign", "nSign")):
    off = d.find(want)
    va = None
    for p in e.segments:
        if p["type"] == 1 and p["offset"] <= off < p["offset"] + p["filesz"]:
            va = p["vaddr"] + (off - p["offset"])
    print("%-9s file=%s va=%s %r"
          % (tag, hex(off), hex(va) if va else "?", d[off:off + 55]))
    if va:
        show_data(va, "JNI name " + tag)

# 2. .data.rel.ro pointers landing in .text -> JNI bodies / VM entry
base = e.byname[".data.rel.ro"]
import struct
n = base["size"] // 8
qw = struct.unpack_from("<%dQ" % n, d, base["offset"])
t0, t1 = text["addr"], text["addr"] + text["size"]
print("\n.data.rel.ro pointers into .text:")
for i in range(n):
    if t0 <= qw[i] < t1:
        print("  relro+%s -> text+%s" % (hex(i * 8), hex(qw[i] - t0)))

# 3. the big .text constant array the VM walks (the 'va table'): find qword runs
#    that point at our known rodata/JAVA_UTF8 markers? instead list the densest
#    .text ADRP targets (likely static tables)
from collections import Counter
c = Counter({va: cvs for va, cvs in by_data.items()})
print("\ntop .text adrp targets:")
for va, cvs in c.most_common(15):
    print("  %s refs=%d" % (hex(va), len(cvs)))
print("done")