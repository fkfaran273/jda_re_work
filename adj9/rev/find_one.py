#!/usr/bin/env python3
"""find_one.py <dex> — per-dex scan for H producers (see find_hsign.py docstring)."""
import os, sys
from loguru import logger
logger.remove()
from androguard.misc import AnalyzeDex
from androguard.core.analysis.analysis import ExternalMethod

DEX = sys.argv[1]
sys.stdout.reconfigure(line_buffering=True)
NEEDLES = ["adj_verification", "Signature signature=", "adj_signing_id",
           "HmacSHA256", "nSign", "headers_id", "native_version",
           "algorithm=\"adj9", "Client-SDK"]
CRYPTO = ["Ljavax/crypto/Mac;", "Ljava/security/Mac;"]

a, d, dx = AnalyzeDex(DEX)
print(f"=== {os.path.basename(DEX)} classes={len(d.get_classes())}", flush=True)
for m in d.get_methods():
    if m.get_name() != "nSign":
        continue
    flags = (m.get_access_flags_string()
             if hasattr(m, "get_access_flags_string") else "?")
    print(f"  [nSign decl] {m.get_class_name()} {m.get_descriptor()} {flags}", flush=True)
for s in dx.get_strings():
    v = s.get_value()
    if not any(n in v for n in NEEDLES):
        continue
    if len(v) > 90:
        v = v[:90] + "..."
    cls = sorted({x[1].get_class_name() for x in s.get_xref_from()})[:8]
    print(f"  [str] {v!r} -> {cls}", flush=True)
for meth in dx.get_methods():
    em = meth.get_method()
    if not isinstance(em, ExternalMethod) or em.get_class_name() not in CRYPTO:
        continue
    if em.get_name() not in ("getInstance", "doFinal", "init"):
        continue
    callers = sorted({x.get_class_name() + "->" + x.get_name()
                      for x in meth.get_xref_from()})[:12]
    if callers:
        print(f"  [crypto] Mac.{em.get_name()} <- {callers}", flush=True)
