# Round 2: byte-granular read-16x runs (key block), full sbox table dump,
# count profile around the table. Saves counter for offline analysis.
import sys, os, struct, collections, pickle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *

OUT = os.path.dirname(os.path.abspath(__file__))
params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
e = Emu()
cnt = collections.Counter()
def hr(uc, access, address, size, value, ud):
    cnt[address] += 1
e.uc.hook_add(UC_HOOK_MEM_READ, hr, begin=1, end=0xFFFFFFFFFFFFFFFF)
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
pickle.dump(dict(cnt), open(os.path.join(OUT, "cnt_full.pkl"), "wb"))
print("blob", out[:16].hex())

# the dword table @0x900e3e8: dump 320 dwords with counts
T0 = 0x900e3e8
prof = []
for k in range(320):
    a = T0 + 4 * k
    prof.append(cnt.get(a, 0))
print("table read-count profile (first 320 dwords):")
print(prof[:80])
print(prof[80:160])
print(prof[160:240])
print(prof[240:320])

# full table bytes (first 256 entries)
heap = bytes(e.uc.mem_read(HEAP, e.brk - HEAP))
tab = heap[T0 - HEAP: T0 - HEAP + 4 * 256]
bytes_tab = bytes(struct.unpack_from("<256I", tab, 0))
print("table bytes:", bytes_tab.hex())
perm = len(set(bytes_tab)) == 256
print("is permutation of 0..255:", perm)
open(os.path.join(OUT, "vm_sbox.bin"), "wb").write(bytes_tab)

# byte-stride contiguous runs of read-16x addresses
by16 = sorted(a for a, k in cnt.items() if k == 16)
runs = []
run = []
for a in by16:
    if run and a == run[-1] + 1:
        run.append(a)
    else:
        if len(run) >= 16:
            runs.append(run)
        run = [a]
if len(run) >= 16:
    runs.append(run)
print("byte runs >=16B of read-16x:", len(runs))
for r in runs[:20]:
    lo = r[0]; ln = len(r)
    if HEAP <= lo < HEAP + 0x800000:
        data = heap[lo - HEAP: lo - HEAP + ln]
        print("  heap @%#x len=%d: %s" % (lo, ln, data[:80].hex()))
        open(os.path.join(OUT, "brun_%x.bin" % lo), "wb").write(data)
    else:
        try:
            data = bytes(e.uc.mem_read(lo, ln))
            print("  lib  @%#x len=%d: %s" % (lo, ln, data[:80].hex()))
            open(os.path.join(OUT, "brun_%x.bin" % lo), "wb").write(data)
        except Exception as ex:
            print("  @%#x read fail" % lo)
