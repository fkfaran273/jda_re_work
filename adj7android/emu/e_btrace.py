# Full-run heap write trace: find where record field b (32 B) is first
# produced, and capture the timeline (claims string -> b -> record).
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP, STACK, STACK_SZ
from unicorn import *
from unicorn.arm64_const import *

params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "attribution", "client_sdk": "android5.6.0",
          "app_version": "3.0.4", "environment": "production",
          "event_token": "abcdef", "os_name": "android", "os_version": "12",
          "seq": "9"}

e = Emu()
e.nonce12 = bytes.fromhex("00112233445566778899AABB")
writes = []
def hw(uc, access, address, size, value, ud):
    if HEAP <= address < HEAP + 0x800000 or STACK <= address < STACK + STACK_SZ:
        writes.append((uc.reg_read(UC_ARM64_REG_PC), address, size, value))
e.uc.hook_add(UC_HOOK_MEM_WRITE, hw)
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
print("blob", out[:16].hex())
json.dump({"blob": out.hex(), "writes": writes},
          open("e_btrace.json", "w"))
print("writes captured:", len(writes))

# b dwords (BE word view of b hex) and LE
blob = out
# we don't know b yet: read it from the record... derive from mint: same
# params+nonce as agent D mint2 -> b2 known:
b2 = bytes.fromhex("BDCFFCBACB96096B39AB4586713B393E88E4773DF8D5B2F5E847B5C38F9D9C29")
bwords = struct.unpack(">8I", b2)
bwords_le = struct.unpack("<8I", b2)
targets = set(bwords) | set(bwords_le)
first = {}
for i, (pc, addr, size, value) in enumerate(writes):
    if size == 4 and value in targets and value not in first:
        first[value] = (i, pc, addr)
for v in sorted(first, key=lambda v: first[v][0]):
    i, pc, addr = first[v]
    print("val %08x first@write#%d pc rva=%#x addr=%#x" % (v, i, pc - 0x400000, addr))
items = sorted(first.values())
if items:
    i0 = items[0][0]
    print("context:")
    for pc, addr, size, value in writes[max(0, i0 - 30):i0 + 30]:
        print("  pc rva=%#x addr=%#x sz=%d val=%08x" % (pc - 0x400000, addr, size, value))
