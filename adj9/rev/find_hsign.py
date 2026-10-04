#!/usr/bin/env python3
"""find_hsign.py — locate the Java code that computes H (nSign arg3) in the dex.

Uses androguard (installed): for each classes*.dex find
  1. the class declaring native method `nSign`
  2. methods referencing strings: adj_verification / Signature signature= /
     adj_signing_id / HmacSHA256
  3. invoke sites of javax/crypto/Mac->getInstance / doFinal, with caller class
"""
import os, sys, glob
from androguard.misc import AnalyzeDex
from androguard.core.analysis.analysis import ExternalMethod

ROOT = r"C:\Users\Apps\Downloads\com.penti.app\extracted\base"
sys.stdout.reconfigure(line_buffering=True)
NEEDLES = ["adj_verification", "Signature signature=", "adj_signing_id",
           "HmacSHA256", "nSign", "headers_id", "native_version"]
CRYPTO = ["Ljavax/crypto/Mac;", "Ljava/security/Mac;"]

for dex in sorted(glob.glob(os.path.join(ROOT, "classes*.dex"))):
    a, d, dx = AnalyzeDex(dex)
    print(f"=== {os.path.basename(dex)} classes={len(d.get_classes())}")
    # 1. native nSign declarer
    for m in d.get_methods():
        if m.get_name() == "nSign" and m.get_descriptor().startswith("("):
            print(f"  [nSign decl] {m.get_class_name()} {m.get_descriptor()} native={m.get_access_flags_string()}")
    # 2. string xrefs
    for s in dx.get_strings():
        v = s.get_value()
        if not any(n in v for n in NEEDLES):
            continue
        if len(v) > 80:
            v = v[:80] + "..."
        xrefs = list(s.get_xref_from())
        cls = sorted({x[1].get_class_name() for x in xrefs})[:6]
        print(f"  [str] {v!r} -> {cls}")
    # 3. Mac.getInstance / doFinal call sites
    for meth in dx.get_methods():
        em = meth.get_method()
        if not isinstance(em, ExternalMethod):
            continue
        if em.get_class_name() not in CRYPTO:
            continue
        if em.get_name() not in ("getInstance", "doFinal", "init"):
            continue
        callers = sorted({x.get_class_name() + "->" + x.get_name()
                          for x in meth.get_xref_from()})[:10]
        if callers:
            print(f"  [crypto] Mac.{em.get_name()} <- {callers}")
