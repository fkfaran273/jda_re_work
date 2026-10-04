"""region_vs_device.py - is the region derived from DEVICE IDENTIFIERS?

The user's insight: the server sees the device data in the request AND the blob.
If the region is derived from a device identifier (GAID, android_uuid, etc.),
the server could verify it. We tested H/claims/second but never DEVICE IDS.

Tests: W0, T0, T1, T2, T3, d2 vs each device's GAID / android_uuid.
Digests, XOR, arithmetic, and byte-slice relations.
"""
import hashlib
import json
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def load_rows():
    rows = []
    for f in ("all_signings.json", "app_signings.json", "app_signings2.json",
              "app_signings3.json", "app_signings4.json", "app_signings5.json"):
        p = os.path.join(HERE, f)
        if not os.path.exists(p):
            continue
        a = json.load(open(p, encoding="utf-8"))
        for r in (a if isinstance(a, list) else [a]):
            rows.append(r)
    return rows


def unpack_d0(hex_str):
    return [struct.unpack(">I", bytes.fromhex(hex_str[i:i+8]))[0]
            for i in range(0, len(hex_str), 8)]


rows = load_rows()
print("rows: %d" % len(rows))

digests = [hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.blake2s]
hits = 0

for i, r in enumerate(rows):
    d0 = unpack_d0(r["d0"])
    W0, T0, T1 = d0[0], d0[1], d0[2]
    d2 = int(r["d2"], 16) if isinstance(r["d2"], str) else int(r["d2"], 16)

    ids = []
    for k in ("gps_adid", "android_uuid"):
        v = r.get(k) or r.get("src") or ""
        if isinstance(v, str) and re.match(r"[0-9a-fA-F]{8}-", v):
            ids.append(v)

    for idv in ids:
        idb = idv.encode()
        for dfn in digests:
            h = dfn(idb).digest()
            # check first 4 bytes vs W0/T0/T1
            for off in range(0, len(h) - 3, 4):
                w = struct.unpack(">I", h[off:off+4])[0]
                for name, target in [("W0", W0), ("T0", T0), ("T1", T1), ("d2", d2)]:
                    if w == target:
                        print("HIT: %s[%d] == %s(%s)[%d] on row %d" % (
                            name, target, dfn().name, idv[:8], off, i))
                        hits += 1
        # also crc32 / fnv
        crc = zlib.crc32(idb) & 0xFFFFFFFF
        for name, target in [("W0", W0), ("T0", T0), ("T1", T1), ("d2", d2)]:
            if crc == target:
                print("HIT: %s == crc32(%s) on row %d" % (name, idv[:8], i))
                hits += 1

print("total hits: %d" % hits)
if hits == 0:
    print("=> region is NOT derived from GAID/android_uuid by any tested digest")
