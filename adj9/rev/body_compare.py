"""DEFINITIVE body check: run native nSign and Python mint_blob on IDENTICAL
inputs (same claims map, same seed, same second, same cert SHA1) and compare
the two 192-byte envelopes byte-for-byte.  Any difference localizes a FinEx
body-layout bug; a full match proves the offline signer is byte-exact and any
remaining Organic is a click/anti-fraud issue, not a signature issue.
"""
import os, sys, struct, json, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "adj9_tool")))
sys.path.insert(0, HERE)
os.chdir(os.path.join(HERE, "..", ".."))

import emu_8d6f4 as E
import adj9_signer as S
from native_d0 import posthead_region_native
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

SEED = 0x5a9b1400
SEC = 1789240512
CERT = bytes.fromhex(S.D9_HEX)   # fad0f10d... the real app cert SHA1 (d9)

# A realistic SESSION claim set (the desc10 law keys).  claims_from_wire adds
# the internal claims (activity_kind, adj_verification, client_sdk, ...).
params = {
    "api_level": "31", "app_token": "jut9tib0eeps", "app_version": "3.13.9",
    "gps_adid": "cc87d5c7-46cf-47db-8209-b138c922aca7",
    "android_uuid": "11111111-2222-3333-4444-555555555555",
    "created_at": "2026-09-25T12:00:00.000Z+0000", "sent_at": "2026-09-25T12:00:00.500Z+0000",
    "installed_at": "2026-09-25T11:59:00.000Z+0000", "updated_at": "2026-09-25T11:59:00.000Z+0000",
    "device_name": "moto g42", "device_type": "phone", "device_manufacturer": "motorola",
    "os_name": "android", "os_version": "12", "os_build": "S2SE32.28-28-4",
    "hardware_name": "S2SE32.28-28-4", "language": "tr", "package_name": "com.penti.app",
    "environment": "production", "gps_adid_src": "service", "session_count": "1",
    "store_name_from_system": "com.android.vending", "initiating_package_name": "com.android.vending",
    "tracking_enabled": "1", "connectivity_type": "1", "display_width": "1080",
    "display_height": "2237", "screen_size": "normal", "screen_density": "high",
    "screen_format": "long", "cpu_type": "arm64-v8a",
}
val = S.claims_from_wire(params, "session")
# every desc10-law value the native must see in its map.  default=None makes
# the harness's containsKey return False for any key we did NOT list, so the
# native's claim map carries exactly the session claims (no injected values).
strvals = {k: v for k, v in val.items() if v is not None}
strvals["default"] = None

# ---- native nSign under the harness, with a post-head d0 capture ----------
cfg = dict(E.DEF_CFG)
cfg["urandom8"] = SEED.to_bytes(4, "little") + b"\x11\x22\x33\x44"
cfg["sec"] = SEC
cfg["time_sec"] = SEC
cfg["usec"] = 500000
cfg["strvals"] = strvals
cfg["cert_sha1"] = CERT
e = E.Emu(cfg)
mu = e.mu
cap = {"ctx": None, "d0": None, "d4": None}

def _snap(addr, n):
    return [struct.unpack_from("<H", bytes(mu.mem_read(addr, 2 * n)), 2 * i)[0] for i in range(n)]

def h_pm(uc, addr, size, ud):
    c = uc.reg_read(UC_ARM64_REG_X19)
    cap["ctx"] = c
    cap["d4"] = _snap(c + 0x10, 16)
def h_ret(uc, addr, size, ud):
    c = cap.get("ctx")
    if c is not None and cap.get("d0") is None:
        cap["d0"] = _snap(c + 0x30, 72)

mu.hook_add(UC_HOOK_CODE, h_pm, begin=0x1437C8, end=0x1437C8)
mu.hook_add(UC_HOOK_CODE, h_ret, begin=0xDB1C4, end=0xDB1C4)

print("running native nSign ...", flush=True)
t0 = time.time()
st = e.run(0xDB1CC, count=400_000_000, argstyle="nsign")
nat = e.result.get("blob") or b""
print("native stopped=%s wall=%.1fs blob_len=%d" % (st, time.time() - t0, len(nat)), flush=True)
if not cap.get("d0"):
    raise SystemExit("post-head d0 capture MISSING; cannot compare")

def pack(hw):
    raw = b"".join(h.to_bytes(2, "little") for h in hw)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, len(raw), 4)]

region = (pack(cap["d0"]), int.from_bytes(SEED.to_bytes(4, "little"), "big"), pack(cap["d4"]))

# ---- Python mint_blob on the same inputs, fed the native post-head d0 ------
py, info = S.mint_blob(val, "session", second=SEC, region=region,
                       d8_hex=S.D8_HEX, d9_hex=S.D9_HEX)
print("python blob_len=%d status=%s" % (len(py), info["status"]), flush=True)
print("d10 unpadded=%d" % info["desc10_unpadded"])

print("\nnative_len=%d python_len=%d" % (len(nat), len(py)))
if len(nat) != len(py):
    print("LENGTH MISMATCH: native %d vs python %d" % (len(nat), len(py)))
n = min(len(nat), len(py))
diff = [i for i in range(n) if nat[i] != py[i]]
print("differing bytes: %d / %d" % (len(diff), n))
print("native header:", nat[:16].hex())
print("python header:", py[:16].hex())
print("header match:", nat[:16] == py[:16])
if diff:
    w = [i // 4 for i in diff]
    print("differing words (first 24):", sorted(set(w))[:24])
    lo, hi = min(diff), max(diff)
    print("diff span bytes [%d..%d]" % (lo, hi))
    for i in diff[:16]:
        print("  byte %3d: native %02x python %02x" % (i, nat[i], py[i]))
print("\nBODY MATCH:", nat[16:] == py[16:])
json.dump({"native_len": len(nat), "python_len": len(py),
           "native": nat.hex(), "python": py.hex(),
           "ndiff": len(diff), "header_match": nat[:16] == py[:16],
           "body_match": nat[16:] == py[16:]},
          open(os.path.join(HERE, "body_compare.json"), "w"), indent=1)
print("wrote body_compare.json")
