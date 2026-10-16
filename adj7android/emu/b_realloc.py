# b_realloc.py — track PLT realloc/malloc/free to find the buffer lineage
# of the blob array (data ends at SRC=0x900c230); dump buffers whose first
# dword looks like the blob header in BE-dword form.
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE
from unicorn import *
from unicorn.arm64_const import *

PARAMS = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
SECOND = 1791358552
COPY_PC = BASE + 0x10f834
SRC = 0x900c230
BLOB0 = 0x40e0f783            # blob[0:4] as BE dword = array dword0

e = Emu()
ev = {"log": [], "copy": None}
orig = e.plt_dispatch
def spy(uc, name):
    if name == "realloc":
        old, n = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1)
        lr = uc.reg_read(UC_ARM64_REG_LR) - BASE
        r = orig(uc, name)          # performs alloc + host-side copy
        new = uc.reg_read(UC_ARM64_REG_X0)
        rec = {"old": old, "n": n, "new": new, "lr": lr}
        try:
            head = bytes(uc.mem_read(new, 16))
            rec["head"] = head.hex()
            if len(head) >= 4 and struct.unpack_from("<I", head)[0] == BLOB0:
                rec["blob"] = bytes(uc.mem_read(new, 0x140)).hex()
        except UcError:
            pass
        ev["log"].append(rec)
        return new if new is not None else uc.reg_read(UC_ARM64_REG_X0)
    return orig(uc, name)
e.plt_dispatch = spy

def code_hook(uc, address, size, ud):
    if ev["copy"] is None and address == COPY_PC:
        ev["copy"] = "seen"
e.uc.hook_add(UC_HOOK_CODE, code_hook, begin=COPY_PC, end=COPY_PC)
out = e.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
print("reallocs: %d  copy-out seen: %s" % (len(ev["log"]), ev["copy"]))
for i, r in enumerate(ev["log"]):
    mark = "  <<< BLOB ARRAY" if "blob" in r else ""
    print("  [%3d] realloc(old=%#x, n=%d) -> %#x  head=%s  lr rva %#x%s"
          % (i, r["old"], r["n"], r["new"], r.get("head", "")[:32],
             r["lr"], mark))
json.dump(ev["log"], open(os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "b_realloc.json"), "w"))
if any("blob" in r for r in ev["log"]):
    bl = [r for r in ev["log"] if "blob" in r]
    b = bytes.fromhex(bl[-1]["blob"])
    nat = b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))
    print("last blob-array realloc: old=%#x n=%d -> %#x" %
          (bl[-1]["old"], bl[-1]["n"], bl[-1]["new"]))
    print("natural[272:304]:", nat[272:304].hex().upper())
    print("expected     tag:", out[272:304].hex().upper())
