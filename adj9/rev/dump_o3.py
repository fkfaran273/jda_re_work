#!/usr/bin/env python3
"""dump_o3.py — find which classes*.dex defines Lcom/adjust/sdk/sig/o3 (+a0, j1, m3)
and dump their full bytecode to sigsrc_extra.txt.  o3.a(a0)->String builds
'adj_verification' — the missing component of the HMAC message."""
import os, sys, glob
from loguru import logger
logger.remove()
sys.stdout.reconfigure(line_buffering=True)
try:
    from androguard.core.dex import DEX as DVM
except ImportError:
    from androguard.core.bytecodes.dvm import DalvikVMFormat as DVM
ROOT = r"C:\Users\Apps\Downloads\com.penti.app\extracted\base"
WANT = ("o3;", "a0;", "j1;", "m3;")
out = []
for dex in sorted(glob.glob(os.path.join(ROOT, "classes*.dex"))):
    d = DVM(open(dex, "rb").read())
    names = {c.get_name() for c in d.get_classes()}
    hit = [f"Lcom/adjust/sdk/sig/{w[:-1]}" for w in WANT
           if f"Lcom/adjust/sdk/sig/{w[:-1]}" in names or
              f"Lcom/adjust/sdk/sig/{w}" in names]
    if not hit:
        continue
    print(os.path.basename(dex), "->", hit)
    for c in d.get_classes():
        cn = c.get_name()
        if not any(f"sig/{w[:-1]}" in cn for w in WANT):
            continue
        out.append(f"\n########## {cn} ##########")
        for fl in c.get_fields():
            out.append(f"  FIELD {fl.get_name()} : {fl.get_descriptor()}")
        for m in c.get_methods():
            out.append(f"\n--- {m.get_name()} {m.get_descriptor()} flags={m.get_access_flags_string()}")
            code = m.get_code()
            if code is None:
                out.append("  (no code)")
                continue
            for ins in code.get_bc().get_instructions():
                out.append(f"  {ins.get_name()} {ins.get_output()}")
P = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\sigsrc_extra.txt"
open(P, "w", encoding="utf-8").write("\n".join(out))
print("written", P, len(out), "lines")