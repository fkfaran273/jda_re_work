# d_record_mint.py — ONE instrumented emu mint capturing:
#   - claims string assembly (rolling log armed at first 'smxi' dword store)
#   - full 256-B record plaintext (snapshot at the 0x10101010 pad write)
#   - HMAC key K window (snapshot at the 0x36363636 ipad write)
# params chosen to span the claims pool (app_version, environment,
# event_token, os_name, os_version, seq, block2) so the claims law and the
# e-field input are both observable.
import sys, os, json, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *
from unicorn.arm64_const import *

HERE = os.path.dirname(os.path.abspath(__file__))
PARAMS = {
    "app_token": "smxi7gqwu39c",
    "app_version": "3.0.4",
    "environment": "production",
    "event_token": "abcdef",
    "os_name": "android",
    "os_version": "12",
    "package_name": "in.hanafintech",
    "seq": "9",
    "activity_kind": "attribution",
    "client_sdk": "android5.6.0",
}
SECOND = 1791358552
NONCE = "00112233445566778899AABB"

e = Emu()
e.nonce12 = bytes.fromhex(NONCE)

st = {"claims_addr": None, "log": [], "snaps": [], "t0": time.time()}

def snap(uc, addr, back, fwd, tag):
    try:
        buf = bytes(uc.mem_read(addr - back, back + fwd))
    except UcError:
        return
    st["snaps"].append((tag, addr, buf.hex()))

def hw(uc, access, address, size, value, ud):
    if size != 4:
        return
    v = value & 0xFFFFFFFF
    if st["claims_addr"] is None:
        if v == 0x736D7869:            # 'smxi' — claims string start
            st["claims_addr"] = address
            snap(uc, address, 0x40, 0x200, "claims_arena_arm")
        return
    lo, hi = st["claims_addr"] - 0x40, st["claims_addr"] + 0x240
    if not (lo <= address < hi):
        return
    if len(st["log"]) < 20000:
        st["log"].append((uc.reg_read(UC_ARM64_REG_PC) - BASE,
                          address - st["claims_addr"], v))
    if v == 0x10101010:                # record pad -> full record snapshot
        snap(uc, address, 300, 64, "record")
    elif v == 0x36363636:              # ipad -> K window snapshot
        snap(uc, address, 0x60, 0x48, "ipad_K")

e.uc.hook_add(UC_HOOK_MEM_WRITE, hw, begin=HEAP, end=HEAP + 0x20000)

out = e.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
print("mint took %.1fs, out=%s" % (time.time() - st["t0"],
                                   out.hex().upper() if out else None))
print("claims_addr=%s log=%d snaps=%d" %
      (hex(st["claims_addr"]) if st["claims_addr"] else None,
       len(st["log"]), len(st["snaps"])))
json.dump({
    "params": PARAMS, "second": SECOND, "nonce": NONCE,
    "blob": out.hex() if out else None,
    "srand": e.srand_seeds, "map_reads": e.map_reads,
    "claims_addr": st["claims_addr"], "log": st["log"],
    "snaps": st["snaps"],
}, open(os.path.join(HERE, "d_rec_mint.json"), "w"))
print("saved d_rec_mint.json")
