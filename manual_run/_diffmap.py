"""_diffmap.py — differential analysis: which input moves which output bit?

Neither agent is doing this.  We have a working signer, so we can mint
arbitrary inputs and observe the response.  Vary ONE descriptor at a time and
measure which bits of block32 and the trailer move.

If an output depends on everything -> it is a mixing function and the
per-input structure is what we want to know.  If some outputs depend on only
one input, that is a shortcut.
"""
import os
import struct
import sys

sys.path.insert(0, ".")
import adj9_signature as SG

OUT = "_diffmap_out.txt"


def mint(claims, second, seed, kind="session"):
    blob, _s, _i = SG.sign_request(claims, kind, second=second, seed=seed)
    dec = SG.decode_blob(blob)
    return dec["record"][46:78], blob[160:192]


def diff(a, b):
    return sum(1 for x, y in zip(a, b) if x != y)


base_claims = {
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "activity_kind": "session",
    "android_uuid": "11111111-2222-4333-8444-555555555555",
    "api_level": "31",
    "app_token": "i2n2e5kmcpvk",
    "app_version": "1.0.174",
    "attribution_deeplink": "1",
    "client_sdk": "flutter5.8.0@android5.8.0",
    "connectivity_type": "1",
    "country": "IN",
    "cpu_type": "arm64-v8a",
    "created_at": "2026-09-30T12:00:00.928Z+0530",
    "device_manufacturer": "Xiaomi",
    "device_name": "23090RA98I",
    "device_type": "phone",
    "display_height": "2712",
    "display_width": "1220",
    "environment": "production",
    "foreground": "1",
    "gps_adid": "99999999-8888-4777-8666-555555555555",
    "gps_adid_attempt": "1",
    "gps_adid_src": "service",
    "hardware_name": "qcom",
    "initiating_package_name": "com.android.vending",
    "installed_at": "2026-09-30T11:59:07.774Z+0530",
    "language": "tr",
    "needs_response_details": "1",
    "offline_mode_enabled": "0",
    "os_build": "V1TD35H.83-20-5",
    "os_name": "android",
    "os_version": "15",
    "package_name": "com.creditsea.app",
    "screen_density": "high",
    "screen_format": "long",
    "screen_size": "normal",
    "sent_at": "2026-09-30T12:00:00.942Z+0530",
    "session_count": "1",
    "store_name_from_system": "com.android.vending",
    "tracking_enabled": "1",
    "ui_mode": "1",
    "updated_at": "2026-09-30T11:59:07.774Z+0530",
}

SEC = 1789000000
SEED_A = 0xDEADBEEF
SEED_B = 0xDEADBEEE

lines = []
b0, t0 = mint(base_claims, SEC, SEED_A)
lines.append("base block32 %s" % b0.hex())
lines.append("base trailer  %s" % t0.hex())
lines.append("")

# 1. vary ONLY the seed
b1, t1 = mint(base_claims, SEC, SEED_B)
lines.append("SEED only changed   -> block32 %d/32 bits, trailer %d/32 bits"
             % (diff(b0, b1), diff(t0, t1)))

# 2. vary ONE claim value at a time
lines.append("")
lines.append("single-claim sensitivity (block32 / trailer bits changed):")
for key in sorted(base_claims):
    if key in ("activity_kind", "adj_verification"):
        continue
    c = dict(base_claims)
    c[key] = c[key] + "X"          # any different value
    try:
        b, t = mint(c, SEC, SEED_A)
    except Exception as e:
        lines.append("  %-26s ERROR %r" % (key, e))
        continue
    lines.append("  %-26s %2d / %2d" % (key, diff(b0, b), diff(t0, t)))

# 3. vary the signing second
b2, t2 = mint(base_claims, SEC + 1, SEED_A)
lines.append("")
lines.append("SECOND changed      -> block32 %d/32, trailer %d/32"
             % (diff(b0, b2), diff(t0, t2)))

text = "\n".join(lines)
open(OUT, "w").write(text)
print(text)
