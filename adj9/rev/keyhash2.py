# keyhash2.py - try UNSIGNED (not Java-signed) 64-bit hashes of the map keys against
# the 18 nSign tag constants. Java unsigned right shift fragments (>>> 24) and the
# (h | 0) style imply the SDK uses a 64-bit multiply-shift mixer over a per-key
# seed; try the common unsigned families first.
import hashlib
import struct
import sys
import zlib


def u64(x):
    return x & 0xFFFFFFFFFFFFFFFF


def s64(x):
    x &= 0xFFFFFFFFFFFFFFFF
    return x - 0x10000000000000000 if x >= 0x8000000000000000 else x


TAGS = [0xbbcdb763a58a1381, 0xbdc75f3a69fdfe0a, 0xc90b48ac2c50507b,
        0x0b13833959321968, 0x10231d602ac8ea12, 0x204aa50d0566b3d0,
        0x56dec5df28696436, 0x77a415f427955cb8, 0x7e88f56dc0586dbb,
        0x7f7443cd4e147408, 0xfe6b55aad72bcdf8, 0xf201dec28c3e25ce,
        0x48fe7dcf52dd4c0d, 0x3b4ab7629f5e1dac, 0x32821f94a0780754,
        0x26809d0616d60092, 0x2516ffeb9cc1b031, 0x22dbab5fa06d7801]
TS = set(TAGS)

KEYS = ["store_name_from_system", "gps_adid_attempt", "api_level", "hardware_name",
        "app_version", "app_token", "installed_at", "created_at", "wait_total",
        "device_type", "language", "gps_adid", "foreground", "connectivity_type",
        "device_manufacturer", "display_width", "device_name", "needs_response_details",
        "os_build", "updated_at", "cpu_type", "retry_count", "screen_size",
        "screen_format", "last_error", "gps_adid_src", "wait_time", "os_version",
        "first_error", "android_uuid", "sent_at", "offline_mode_enabled",
        "environment", "screen_density", "attribution_deeplink", "session_count",
        "display_height", "package_name", "initiating_package_name", "os_name",
        "ui_mode", "enqueue_size", "tracking_enabled", "adj_signing_id",
        "activity_kind", "client_sdk", "headers_id", "native_version",
        "adj_verification", "algorithm", "referrer", "app_version_code"]


def m64(a, b):
    return u64(a * b)


def rotl(x, r):
    return u64((x << r) | (x >> (64 - r)))


def fnv(b):
    h = 0xCBF29CE484222325
    for c in b:
        h = m64(h ^ c, 0x100000001B3)
    return h


def jin(b, m):
    h = 0
    for c in b:
        h = m64(m * h ^ c, 1)
    return u64(h)


def jin_add(b, m):
    h = 0
    for c in b:
        h = u64(m * h + c)
    return u64(h)


def jin_sdbm(b):
    h = 0
    for c in b:
        h = u64(c + (h << 6) + (h << 16) - h)
    return h


def crc64_ecma(b):
    return crc64(b, 0xC96C5795D7870F42, False)


def crc64_iso(b):
    return crc64(b, 0xD800000000000000, True)


def crc64(b, poly, refin):
    crc = 0xFFFFFFFFFFFFFFFF
    if refin:
        for c in b:
            crc ^= c
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        return u64(crc ^ 0xFFFFFFFFFFFFFFFF)
    for c in b:
        crc ^= (c << 56)
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFFFFFFFFFFFFFF if crc >> 63 else (crc << 1) & 0xFFFFFFFFFFFFFFFF
    return u64(crc ^ 0xFFFFFFFFFFFFFFFF)


def murmur(b):
    m = 0xC6A4A7935BD1E995
    h = 0
    n = len(b) - len(b) % 8
    for i in range(0, n, 8):
        k = struct.unpack_from("<Q", b, i)[0]
        k = m64(k, m)
        k ^= k >> 47
        k = m64(k, m)
        h ^= k
        h = m64(h, m)
    tail = b[n:]
    v = 0
    for i, c in enumerate(tail):
        v |= c << (8 * i)
    if tail:
        h ^= v
        h = m64(h, m)
    h ^= h >> 47
    h = m64(h, m)
    h ^= h >> 47
    return h


CANDS = {
    "fnv1a64": fnv,
    "mul31xor": lambda b: jin(b, 31),
    "mul33xor": lambda b: jin(b, 33),
    "mul33add": lambda b: jin_add(b, 33),
    "sdbm": jin_sdbm,
    "crc64_ecma": crc64_ecma,
    "crc64_iso": crc64_iso,
    "murmur64a": murmur,
    "sha256_64le0": lambda b: struct.unpack_from("<Q", hashlib.sha256(b).digest())[0],
    "sha256_64be0": lambda b: struct.unpack_from(">Q", hashlib.sha256(b).digest())[0],
    "md5_64le0": lambda b: struct.unpack_from("<Q", hashlib.md5(b).digest())[0],
}


print("=== key-tag matches (TAGS=%d, KEYS=%d) ===" % (len(TAGS), len(KEYS)))
tot = 0
for fname, fn in CANDS.items():
    hits = []
    for kk in KEYS:
        v = fn(kk.encode()) & 0xFFFFFFFFFFFFFFFF
        if v in TS:
            hits.append((kk, v))
    if hits:
        print("  %-12s %d hits" % (fname, len(hits)))
        for kk, v in hits[:8]:
            print("      %-28s %016x" % (kk, v))
        tot += len(hits)
print("total:", tot)
print("done")