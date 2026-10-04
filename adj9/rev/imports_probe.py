"""imports_probe.py - what does libsigner.so import? (RNG/time/thread sources)

Lists ELF imports and flags names related to randomness, time, threads,
memory. Uses rev/elf.py ELF class (imports dict name->plt va).
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from elf import ELF
LIB = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
e = ELF(LIB)
names = sorted(e.imports.keys())
print("total imports: %d" % len(names))
for n in names:
    print("  " + n)
print()
KEYS = ("rand", "random", "urandom", "getentropy", "getrandom", "time",
        "clock", "pthread", "malloc", "calloc", "mmap", "getpid", "gettid",
        "ssl", "crypto", "mbedtls", "java", "jni", "secure")
print("=== keyword hits ===")
hit = 0
for n in names:
    ln = n.lower()
    if any(k in ln for k in KEYS):
        print("  HIT " + n)
        hit += 1
print("keyword hits: %d" % hit)
