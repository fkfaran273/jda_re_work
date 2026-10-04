"""time_posthead.py — how long does ONE real-native region lift take?

P4a of diff_paired.py calls adj9_signer.region() -> native_d0.posthead_region_native,
which drives the REAL libsigner nSign under Unicorn with count=400_000_000.
That is the expensive path; measure it once so the differ's runtime is
predictable and so a failure can be told apart from mere slowness.
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "signer"))
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")

SEED = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xD124F72B

t0 = time.time()
import native_d0                                            # noqa: E402

print("[time] import native_d0: %.1fs" % (time.time() - t0), flush=True)

t0 = time.time()
d0, d2, d4 = native_d0.posthead_region_native(SEED)
el = time.time() - t0
print("[time] posthead_region_native(seed=%#x): %.1fs" % (SEED, el), flush=True)
print("d2=%#010x" % d2)
print("d0[:8]=%s" % " ".join("%08x" % x for x in d0[:8]))
print("d4=%s" % " ".join("%08x" % x for x in d4))
