"""Decompile com.adjust.sdk.sig core classes + adjust_keys prefs users from classes3.dex.

Usage: python decompile_sig.py [ClassName ...]   (short names, e.g. Signer NativeLibHelper u2)
With no args: default target list + string-xref scan for adjust_keys/encrypted_key/libsigner.
Writes .java files to adj9/rev/java_src/ and prints a field summary.
"""
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))  # workspace root
sys.path.insert(0, "adj9")

DEX = "adj9/dex/classes3.dex"
OUT = "adj9/rev/java_src"

from androguard.misc import AnalyzeDex
from androguard.decompiler.decompiler import DecompilerDAD

print("[*] analyzing", DEX, "... (slow, ~minutes)")
h, d, dx = AnalyzeDex(DEX)
dc = DecompilerDAD(d, dx)
print("[*] analysis done")

sig_classes = {}
for c in d.get_classes():
    name = c.get_name()  # Lcom/adjust/sdk/sig/Signer;
    if name.startswith("Lcom/adjust/sdk/sig/"):
        sig_classes[name] = c
print(f"[*] {len(sig_classes)} sig classes")


def short_to_lname(s):
    if s.startswith("L") and s.endswith(";"):
        return s
    return f"Lcom/adjust/sdk/sig/{s};"


def access_str(flags):
    names = []
    table = [(0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"),
             (0x10, "final"), (0x20, "synchronized"), (0x400, "abstract"), (0x1000, "synthetic"),
             (0x800, "transient"), (0x40, "volatile"), (0x80, "varargs"), (0x40_0000_0, "enum")]
    for bit, nm in table:
        if flags & bit:
            names.append(nm)
    return " ".join(names)


def dump_class(lname, decompile=True):
    c = sig_classes.get(lname)
    if c is None:
        print(f"[!] class {lname} not found in sig package")
        return
    print(f"\n===== {lname} (extends {c.get_superclassname()}) =====")
    for f in c.get_fields():
        print(f"  FIELD {access_str(f.get_access_flags())} {f.get_descriptor()} {f.get_name()}")
    for m in c.get_methods():
        print(f"  METHOD {access_str(m.get_access_flags())} {m.get_name()} {m.get_descriptor()}")
    if decompile:
        fn = os.path.join(OUT, lname[1:-1].replace("/", "_") + ".java")
        with open(fn, "w", encoding="utf-8") as fh:
            fh.write(f"// decompiled from classes3.dex by androguard DAD\n")
            fh.write(f"// class {lname} extends {c.get_superclassname()}\n\n")
            fh.write(f"// ---- field summary ----\n")
            for f in c.get_fields():
                fh.write(f"// {access_str(f.get_access_flags())} {f.get_descriptor()} {f.get_name()}\n")
            fh.write(f"\n")
            try:
                src = dc.get_source_class(c.get_class_item() if hasattr(c, "get_class_item") else c)
                fh.write(src)
            except Exception as e:
                fh.write(f"// CLASS DECOMPILE FAILED: {e}\n// ---- bytecode fallback ----\n")
                for m in c.get_methods():
                    fh.write(f"// ==== METHOD {m.get_name()}{m.get_descriptor()} ====\n")
                    try:
                        for ins in m.get_instructions():
                            fh.write(f"    {ins.get_name()} {ins.get_output()}\n")
                    except Exception as e2:
                        fh.write(f"// bytecode failed too: {e2}\n")
                    fh.write("\n")
        print(f"  -> wrote {fn}")


def find_string_users(needle):
    """Return (class, method) list of everything referencing a string constant."""
    res = []
    for s in dx.find_strings(needle):
        if s.get_value() != needle:
            continue
        for meth in s.get_xref_from():
            try:
                res.append((meth.get_class_name(), meth.get_name() + meth.get_descriptor()))
            except Exception:
                res.append((str(meth), "?"))
    return res


if __name__ == "__main__":
    args = sys.argv[1:]
    if args:
        for a in args:
            dump_class(short_to_lname(a))
        sys.exit(0)

    # 1. string xrefs
    for needle in ["adjust_keys", "encrypted_key", "signer", "AndroidKeyStore", "HmacSHA256"]:
        print(f"\n[*] string users of {needle!r}:")
        for cls, meth in find_string_users(needle):
            print(f"    {cls} -> {meth}")

    # 2. decompile the WHOLE sig package
    for lname in sorted(sig_classes):
        dump_class(lname)
