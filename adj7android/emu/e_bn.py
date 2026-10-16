# Does record field b depend on the nonce? Two mints, same params,
# different forced nonces; snapshot the record buffer (0x9004e40 LE domain).
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP
from unicorn import *
from unicorn.arm64_const import *

params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "attribution", "client_sdk": "android5.6.0",
          "app_version": "3.0.4", "environment": "production",
          "event_token": "abcdef", "os_name": "android", "os_version": "12",
          "seq": "9"}
RECBUF = HEAP + 0x4e40

def mint(tag, nonce_hex):
    e = Emu()
    e.nonce12 = bytes.fromhex(nonce_hex)
    rec = {}
    def hw(uc, access, address, size, value, ud):
        if RECBUF <= address < RECBUF + 0x140:
            # snapshot full buffer at each write; keep the last few
            rec["buf"] = bytes(uc.mem_read(RECBUF, 0x140))
    e.uc.hook_add(UC_HOOK_MEM_WRITE, hw, begin=RECBUF, end=RECBUF + 0x140)
    out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
    buf = rec.get("buf", b"")
    # decode LE-word domain
    dec = b"".join(buf[i:i+4][::-1] for i in range(0, len(buf), 4))
    print("== %s nonce=%s" % (tag, nonce_hex))
    print("   decoded record:", dec[:240])
    json.dump({"nonce": nonce_hex, "blob": out.hex(), "record_le": dec[:256].hex()},
              open("e_bn_%s.json" % tag, "w"))
    return dec

a = mint("n1", "00112233445566778899AABB")
b = mint("n2", "FFEEDDCCBBAA998877665544")
if a and b:
    diff = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
    print("diff positions:", diff[:40])
