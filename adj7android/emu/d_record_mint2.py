# d_record_mint2.py — pass 2 of the record capture: same params/nonce/second
# as d_record_mint.py (blob must reproduce byte-exact); the pad/ipad/opad
# triggers are GLOBAL this time so the record snapshot cannot be missed.
import sys, os, json, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *
from unicorn.arm64_const import *

HERE = os.path.dirname(os.path.abspath(__file__))
PARAMS = json.load(open(os.path.join(HERE, "d_rec_mint.json")))["params"]
SECOND = 1791358552
NONCE = "00112233445566778899AABB"
EXPECT = json.load(open(os.path.join(HERE, "d_rec_mint.json")))["blob"]

e = Emu()
e.nonce12 = bytes.fromhex(NONCE)
st = {"snaps": [], "t0": time.time(), "pad": 0, "ipad": 0, "opad": 0}

def snap(uc, addr, back, fwd, tag):
    try:
        buf = bytes(uc.mem_read(max(addr - back, HEAP), back + fwd))
    except UcError:
        return
    st["snaps"].append((tag, addr, buf.hex()))

def hw(uc, access, address, size, value, ud):
    if size != 4:
        return
    v = value & 0xFFFFFFFF
    if v == 0x10101010 and st["pad"] < 8:
        st["pad"] += 1
        snap(uc, address, 320, 64, "pad%02d" % st["pad"])
    elif v == 0x36363636 and st["ipad"] < 2:
        st["ipad"] += 1
        snap(uc, address, 0x60, 0x48, "ipad%d" % st["ipad"])
    elif v == 0x5C5C5C5C and st["opad"] < 2:
        st["opad"] += 1
        snap(uc, address, 0x60, 0x48, "opad%d" % st["opad"])

e.uc.hook_add(UC_HOOK_MEM_WRITE, hw, begin=HEAP, end=HEAP + 0x20000)
out = e.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
print("mint took %.1fs pad=%d ipad=%d opad=%d snaps=%d" %
      (time.time() - st["t0"], st["pad"], st["ipad"], st["opad"],
       len(st["snaps"])))
print("reproduce:", out.hex() == EXPECT if out else None)
json.dump({"blob": out.hex() if out else None,
           "reproduced": out.hex() == EXPECT if out else False,
           "snaps": st["snaps"]},
          open(os.path.join(HERE, "d_rec_mint2.json"), "w"))
print("saved d_rec_mint2.json")
