#!/usr/bin/env python3
"""find_key_writer.py — locate who WRITES 'encrypted_key'/'adjust_keys' across ALL dexes,
and who references t1 (the HMAC signer) outside the sig package."""
import os, sys, glob
from loguru import logger
logger.remove()
from androguard.misc import AnalyzeDex
ROOT = r"C:\Users\Apps\Downloads\com.penti.app\extracted\base"
sys.stdout.reconfigure(line_buffering=True)
NEEDLES = ["encrypted_key", "adjust_keys"]
for dex in sorted(glob.glob(os.path.join(ROOT, "classes*.dex"))):
    a, d, dx = AnalyzeDex(dex)
    for s in dx.get_strings():
        v = s.get_value()
        if not any(n == v for n in NEEDLES):
            continue
        cls = sorted({x[1].get_class_name() for x in s.get_xref_from()})
        print(f"[{os.path.basename(dex)}] {v!r} -> {cls}", flush=True)
        # per-method detail for the referencing classes
        for meth in dx.get_methods():
            em = meth.get_method()
            if em.get_class_name() not in cls:
                continue
            src = em.get_source() if hasattr(em, "get_source") else ""
            code = getattr(em, "get_code", lambda: None)()
            if code is None:
                continue
            hits = [i.get_name() + " " + i.get_output()
                    for i in code.get_bc().get_instructions()
                    if NEEDLES[0] in (i.get_output() or "") or NEEDLES[1] in (i.get_output() or "")]
            if hits:
                print(f"    {em.get_class_name()}->{em.get_name()}", flush=True)
                for h in hits[:8]:
                    print(f"      {h.strip()}", flush=True)
