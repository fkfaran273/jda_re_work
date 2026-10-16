# Find the round-key schedule: dwords read EXACTLY 16 times during a mint
# (once per body chunk), forming contiguous runs. Also grep heap for the
# record JSON / cert40 / sha256('') markers.
import sys, os, struct, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *
from unicorn.arm64_const import *

OUT = os.path.dirname(os.path.abspath(__file__))

params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
e = Emu()
cnt = collections.Counter()
def hr(uc, access, address, size, value, ud):
    cnt[address] += 1
e.uc.hook_add(UC_HOOK_MEM_READ, hr, begin=1, end=0xFFFFFFFFFFFFFFFF)
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
print("blob", out[:16].hex(), "distinct read addrs", len(cnt))

heap = bytes(e.uc.mem_read(HEAP, e.brk - HEAP))
open(os.path.join(OUT, "heap_full.bin"), "wb").write(heap)
open(os.path.join(OUT, "blob_full.bin"), "wb").write(out)

# markers in heap
for probe in (b'{ "a', b'"a":', b'C1BFAFCA', b'E3B0C44298FC1C14',
              b'c1bfafca', b'e3b0c442'):
    i = heap.find(probe)
    hits = 0
    while i >= 0 and hits < 3:
        print("heap %r @%#x: %r" % (probe, HEAP + i, heap[i:i+96]))
        i = heap.find(probe, i + 1)
        hits += 1
    if not hits:
        print("heap %r: none" % probe)

# dwords read exactly 16 times
sixteen = sorted(a for a, k in cnt.items() if k == 16 and a % 4 == 0)
print("dwords read exactly 16x:", len(sixteen))
# contiguous runs
runs = []
run = []
for a in sixteen:
    if run and a == run[-1] + 4:
        run.append(a)
    else:
        if len(run) >= 8:
            runs.append(run)
        run = [a]
if len(run) >= 8:
    runs.append(run)
print("contiguous runs >= 8 dwords:", len(runs))
for r in runs[:12]:
    lo = r[0]
    ln = len(r) * 4
    where = ("heap" if HEAP <= lo < HEAP + 0x800000 else
             "lib" if BASE <= lo < BASE + 0x120000 else "?")
    try:
        if where == "heap":
            data = heap[lo - HEAP: lo - HEAP + ln]
        else:
            data = bytes(e.uc.mem_read(lo, ln))
        print("  %s @%#x len=%d: %s" % (where, lo, ln, data[:64].hex()))
        open(os.path.join(OUT, "run_%x.bin" % lo), "wb").write(data)
    except UcError:
        print("  read fail @%#x" % lo)
