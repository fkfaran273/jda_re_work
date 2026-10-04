"""siggate2_laws.py — region-law check on live-path F.py regions (fast)."""
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mint_pipeline as M
import F as FMOD

print("=== region laws on LIVE-path F.py regions ===")
ok_all = True
l3_fails = 0
tested = 0
l3_pass = 0
for pid in (M.DEFAULT_PID, 12345, 26530, 1, 65535):
    for sec in (1789239390, int(time.time()), 1789239391):
        for us in (0, 1, 500000, 999999):
            V = M.make_V(sec, us)
            d0b, d2b, d4b = M.resolve_region(V, pid, M.DEFAULT_TID, None)
            laws = M.region_laws(d0b, d4b)
            tested += 1
            l3_fails += 0 if laws["L3_X_eq_U3"] else 1
            l3_pass += 1 if laws["L3_X_eq_U3"] else 0
            ok = laws["L1_tile_Rrep"] and laws["L2_d4_6_hi_eq_R"]
            ok_all &= ok
print("  L1+L2 (the gate laws): %s on %d live regions"
      % (("PASS ALL" if ok_all else "FAIL PRESENT"), tested))
print("  L3 (device corpus law): pass %d/%d" % (l3_pass, tested))

print("\n=== captured-region seed roundtrip (d2 -> seed) ===")
asg = json.load(open(os.path.join(HERE, "all_signings.json")))
for i in (0, 1, 4, 5, 6, 7):
    r = asg[i]
    d2hex = r["d2"]
    d2int = struct.unpack(">I", bytes.fromhex(d2hex))[0]
    seed = struct.pack(">I", d2int)[::-1]  # descriptor = LE store read BE
    d0, d2b, d4 = FMOD.region(int.from_bytes(seed, "little"), 0)
    ok = struct.pack(">I", d2b).hex() == d2hex
    # and: does F.py reproduce the CAPTURED d4 from the recovered seed?
    d4hex = r["d4"]
    d4b = b"".join(struct.pack(">I", w) for w in d4).hex()
    print("  row %d: seed=0x%s d2-roundtrip=%s d4-repro=%s"
          % (i, seed.hex(), ok, d4b == d4hex))

print("\n=== device-captured regions: law rates (ground truth) ===")
l1 = l2 = l3 = n = 0
for r in asg:
    d0b, d4b = bytes.fromhex(r["d0"]), bytes.fromhex(r["d4"])
    laws = M.region_laws(d0b, d4b)
    l1 += laws["L1_tile_Rrep"]
    l2 += laws["L2_d4_6_hi_eq_R"]
    l3 += laws["L3_X_eq_U3"]
    n += 1
print("  device captures: L1 %d/%d L2 %d/%d L3 %d/%d" % (l1, n, l2, n, l3, n))
