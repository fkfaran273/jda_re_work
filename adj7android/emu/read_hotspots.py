# .data/.rodata read-hotspot scan during a mint -> locate KB362 / SEED / DK37.
import sys, os, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE
from unicorn import *
from unicorn.arm64_const import *

DATA_LO = BASE + 0x11bd80
DATA_HI = BASE + 0x11f0da
RODATA_LO = BASE + 0x2fe0
RODATA_HI = BASE + 0x30c8
GOT_LO = BASE + 0x117b70
GOT_HI = BASE + 0x117d80

params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
e = Emu()
counts = collections.Counter()
def hook_read(uc, access, address, size, value, ud):
    counts[(address, size)] += 1
e.uc.hook_add(UC_HOOK_MEM_READ, hook_read, begin=DATA_LO, end=DATA_HI)
e.uc.hook_add(UC_HOOK_MEM_READ, hook_read, begin=RODATA_LO, end=RODATA_HI)
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
print("blob ok:", out is not None)

# aggregate per 32-byte block
blocks = collections.Counter()
for (addr, size), n in counts.items():
    blocks[(addr & ~0x1F) - BASE] += n
print("top read blocks (VA, hits):")
for va, n in blocks.most_common(25):
    print("  VA %08x  %d" % (va, n))

# dump the top few blocks raw + CC-unmasked
uc = e.uc
for va, n in blocks.most_common(8):
    rva = va
    buf = bytes(uc.mem_read(BASE + rva, 64))
    print("== VA %08x (%d reads)" % (rva, n))
    print("   raw    ", buf.hex())
    print("   cc-xor ", bytes(b ^ 0xCC for b in buf).hex())
    print("   55-xor ", bytes(b ^ 0x55 for b in buf).hex())
