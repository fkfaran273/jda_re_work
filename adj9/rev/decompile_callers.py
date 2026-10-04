"""Decompile external callers: AdjustSigner (classes3) and NativeKeys (classes6).
Also dump xrefs to com.adjust.sdk.sig.Signer methods.
"""
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, "adj9")

from androguard.misc import AnalyzeDex
from androguard.decompiler.decompiler import DecompilerDAD


def dump(d, dx, dc, lnames, tag):
    have = {c.get_name(): c for c in d.get_classes()}
    for lname in lnames:
        c = have.get(lname)
        if c is None:
            print(f"[!] {lname} not found")
            continue
        print(f"===== {lname} (extends {c.get_superclassname()}) =====")
        for f in c.get_fields():
            print(f"  FIELD {f.get_access_flags():#06x} {f.get_descriptor()} {f.get_name()}")
        for m in c.get_methods():
            print(f"  METHOD {m.get_access_flags():#06x} {m.get_name()} {m.get_descriptor()}")
        fn = os.path.join("adj9/rev/java_src", tag + "_" + lname[1:-1].replace("/", "_").replace("$", "_") + ".java")
        with open(fn, "w", encoding="utf-8") as fh:
            fh.write(f"// decompiled by androguard DAD from {tag}\n// class {lname}\n\n")
            try:
                fh.write(dc.get_source_class(c.get_class_item() if hasattr(c, "get_class_item") else c))
            except Exception as e:
                fh.write(f"// DECOMPILE FAILED: {e}\n")
        print(f"  -> {fn}")


print("[*] classes3.dex ...")
h, d, dx = AnalyzeDex("adj9/dex/classes3.dex")
dc = DecompilerDAD(d, dx)

# xrefs to Signer methods from outside sig package
print("\n[*] xrefs to Lcom/adjust/sdk/sig/Signer; methods:")
signer = d.get_class("Lcom/adjust/sdk/sig/Signer;")
if signer:
    for m in signer.get_methods():
        ma = dx.get_method(m)
        try:
            for ref_cls, ref_meth, _off in ma.get_xref_from():
                cn = ref_cls.get_name() if hasattr(ref_cls, "get_name") else str(ref_cls)
                if "adjust/sdk/sig" not in cn:
                    print(f"  {cn} -> {m.get_name()}{m.get_descriptor()}")
        except Exception as e:
            print("  xref err", e)

dump(d, dx, dc, ["Lcom/adjust/sdk/AdjustSigner;"], "c3")

# plus any inner/related classes
names = [c.get_name() for c in d.get_classes()
         if c.get_name().startswith("Lcom/adjust/sdk/") and not c.get_name().startswith("Lcom/adjust/sdk/sig/")
         and "AdjustSigner" in c.get_name()]
if names:
    dump(d, dx, dc, names, "c3")

del h, d, dx, dc
print("[*] classes6.dex ...")
h, d, dx = AnalyzeDex("adj9/dex/classes6.dex")
dc = DecompilerDAD(d, dx)
dump(d, dx, dc, ["Lcom/penti/core/data/security/NativeKeys;",
                 "Lcom/penti/core/data/security/NativeKeys$Companion;"], "c6")
print("[*] done")
