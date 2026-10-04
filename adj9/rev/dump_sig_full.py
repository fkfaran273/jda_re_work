#!/usr/bin/env python3
"""dump_sig_full.py — FULL bytecode of every Lcom/adjust/sdk/sig/* class (no filter).
Goal: find who WRITES 'encrypted_key' (SharedPreferences 'adjust_keys'), what
byte[] goes into t1.a(ctx,msg) (HMAC msg), and what the server receives."""
import sys
from androguard.core.dex import DEX

DEXP = r"C:\Users\Apps\Downloads\com.penti.app\extracted\base\classes3.dex"
OUT = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\sigsrc_full.txt"
sys.stdout.reconfigure(line_buffering=True)

d = DEX(open(DEXP, "rb").read())
out, ncls, nmed = [], 0, 0
for c in d.get_classes():
    cn = c.get_name()
    if not cn.startswith("Lcom/adjust/sdk/sig/"):
        continue
    ncls += 1
    out.append(f"\n########## {cn} ##########")
    for f in c.get_fields():
        out.append(f"  FIELD {f.get_name()} : {f.get_descriptor()}")
    for m in c.get_methods():
        nmed += 1
        out.append(f"\n--- {m.get_name()} {m.get_descriptor()} flags={m.get_access_flags_string()}")
        code = m.get_code()
        if code is None:
            out.append("  (no code)")
            continue
        for ins in code.get_bc().get_instructions():
            out.append(f"  {ins.get_name()} {ins.get_output()}")
open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("written", OUT, "classes:", ncls, "methods:", nmed, "lines:", len(out))