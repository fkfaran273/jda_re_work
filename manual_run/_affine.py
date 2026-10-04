"""_affine.py — independent check: is block32 GF(2)-affine in the claim bytes?

Two agents disagree.  One proved it NOT affine via a 4-run residual test; the
other listed linearity as the top untried idea.  Settle it here.

If f is affine over GF(2) in its inputs, then for ANY x1,x2,x3:
    f(x1) ^ f(x2) ^ f(x3) ^ f(x1 ^ x2 ^ x3)  ==  0
We vary the CLAIMS STRING (a direct byte input to the VM), holding the seed
and second fixed, so nothing else moves.
"""
import os
import sys

sys.path.insert(0, ".")
import adj9_signature as SG

BASE = {
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI", "activity_kind": "session",
    "android_uuid": "11111111-2222-4333-8444-555555555555", "api_level": "31",
    "app_token": "i2n2e5kmcpvk", "app_version": "1.0.174",
    "created_at": "2026-09-30T12:00:00.928Z+0530", "device_name": "23090RA98I",
    "device_type": "phone", "environment": "production",
    "gps_adid": "99999999-8888-4777-8666-555555555555",
    "gps_adid_src": "service", "hardware_name": "qcom",
    "initiating_package_name": "com.android.vending",
    "installed_at": "2026-09-30T11:59:07.774Z+0530", "os_build": "V1TD35H.83-20-5",
    "os_name": "android", "os_version": "15", "package_name": "com.creditsea.app",
    "session_count": "1", "store_name_from_system": "com.android.vending",
    "tracking_enabled": "1", "updated_at": "2026-09-30T11:59:07.774Z+0530",
    "client_sdk": "flutter5.8.0@android5.8.0", "headers_id": "10",
    "adj_signing_id": "1500000", "native_version": "5.0.0",
}
SEC = 1789000000
SEED = 0xDEADBEEF


def block32(claims):
    blob, _s, _i = SG.sign_request(claims, "session", second=SEC, seed=SEED)
    return SG.decode_blob(blob)["record"][46:78]


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def vary(key, val):
    c = dict(BASE)
    c[key] = val
    return c


# three independent single-byte perturbations on claims that block32 depends on
x1 = vary("gps_adid", "99999999-8888-4777-8666-555555555556")
x2 = vary("device_name", "23090RA98B")
x3 = vary("os_build", "V1TD35H.83-20-6")

f1 = block32(x1)
f2 = block32(x2)
f3 = block32(x3)

# x1 ^ x2 ^ x3 on the CLAIMS VALUES (GF(2) add = bytewise XOR)
x4 = dict(BASE)
for k in ("gps_adid", "device_name", "os_build"):
    a, b, c = x1[k], x2[k], x3[k]
    x4[k] = "".join(chr(ord(p) ^ ord(q) ^ ord(r)) for p, q, r in zip(a, b, c))
f4 = block32(x4)

res = bytes(a ^ b ^ c ^ d for a, b, c, d in zip(f1, f2, f3, f4))
nz = sum(1 for b in res if b)
print("f(x1) =", f1.hex())
print("f(x2) =", f2.hex())
print("f(x3) =", f3.hex())
print("f(x1^x2^x3) =", f4.hex())
print()
print("RESIDUAL (0 => affine, non-zero => NOT affine):")
print("   ", res.hex())
print("    non-zero bytes: %d / 32" % nz)
print()
print("VERDICT:", "block32 is NOT GF(2)-affine in the claim bytes"
      if nz else "block32 IS affine -- a basis solve would work")
