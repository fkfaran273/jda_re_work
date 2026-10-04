"""_build_cache.py — freeze the capstone decode into a pickle so vm_fast runs
without libsigner.so / capstone at import (and without the 1.35 s disasm)."""
import os, pickle, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REV)
t0 = time.time()
import vm_final as V
fast = [(m, ops, npc) for (m, ops, npc) in V.FAST]
idx = dict(V.IDX)
pcaddr = [i.address for i in V.INS]
blob = {"FAST": fast, "IDX": idx, "PC": pcaddr,
        "lib_sha": (len(open(V.LIB, "rb").read()),)}
p = os.path.join(HERE, "vm_tables.pkl.gz")
import gzip
with gzip.open(p, "wb", compresslevel=6) as f:
    pickle.dump(blob, f, protocol=4)
print("ins=%d  wrote %s (%.1f KB)  %.2fs"
      % (len(fast), p, os.path.getsize(p) / 1024.0, time.time() - t0))
