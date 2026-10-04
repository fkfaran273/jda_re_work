"""Match nSign's 64-bit case constants against hashes of the known map keys.
If the ladder dispatches on key-hash, each arm -> map key, and the arm bodies
show how each descriptor field is built (the #0/#2/#4 construction sites)."""
import hashlib
import struct

KEYS = ["store_name_from_system", "gps_adid_attempt", "api_level",
        "hardware_name", "app_version", "app_token", "installed_at",
        "created_at", "wait_total", "device_type", "language", "gps_adid",
        "foreground", "connectivity_type", "device_manufacturer",
        "display_width", "device_name", "needs_response_details", "os_build",
        "updated_at", "cpu_type", "retry_count", "screen_size",
        "screen_format", "last_error", "gps_adid_src", "wait_time",
        "os_version", "first_error", "android_uuid", "sent_at",
        "offline_mode_enabled", "environment", "screen_density",
        "attribution_deeplink", "session_count", "display_height",
        "package_name", "initiating_package_name", "os_name", "ui_mode",
        "enqueue_size", "tracking_enabled", "adj_signing_id",
        "activity_kind", "client_sdk", "headers_id", "native_version",
        "adj_verification", "algorithm",
        "app_version_code", "referrer", "referrer_api", "source",
        "google_play_instant", "push_token"]

# (const, arm_target) from nsign_fn.log x9 ladder
ARMS = [
    (0xBBCDB763A58A1381, 0xdae48), (0xBDC75F3A69FDFE0A, 0xdb074),
    (0xC90B48AC2C50507B, 0xdadbc), (0xFE6B55AAD72BCDF8, 0xdb120),
    (0x0B13833959321968, 0xdb0b0), (0x10231D602AC8EA12, 0xdb0e8),
    (0x204AA50D0566B3D0, 0xdb05c), (0x26809D0616D60092, 0xdadec),
    (0x3B4AB7629F5E1DAC, 0xdaf44), (0x48FE7DCF52DD4C0D, 0xdaf68),
    (0x56DEC5DF28696436, 0xdb098), (0x77A415F427955CB8, 0xdae60),
    (0x7E88F56DC0586DBB, 0xdb038), (0x7F7443CD4E147408, 0xdad80),
]


def fnv1a64(b):
    h = 0xCBF29CE484222325
    for c in b:
        h = ((h ^ c) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def fnv1_64(b):
    h = 0xCBF29CE484222325
    for c in b:
        h = ((h * 0x100000001B3) ^ c) & 0xFFFFFFFFFFFFFFFF
    return h


def djb2(b):
    h = 5381
    for c in b:
        h = ((h * 33) + c) & 0xFFFFFFFFFFFFFFFF
    return h


def sdbm(b):
    h = 0
    for c in b:
        h = (c + (h << 6) + (h << 16) - h) & 0xFFFFFFFFFFFFFFFF
    return h


def jstr(b):  # Java String.hashCode, 32-bit
    h = 0
    for c in b:
        h = (31 * h + c) & 0xFFFFFFFF
    return h


def murmur3_64(b, seed=0):
    h = seed
    n = len(b) - len(b) % 8
    for i in range(0, n, 8):
        k = struct.unpack_from("<Q", b, i)[0]
        k = (k * 0x87ED55B7DAA19B63) & 0xFFFFFFFFFFFFFFFF
        k = ((k << 31) | (k >> 33)) & 0xFFFFFFFFFFFFFFFF
        k = (k * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        h ^= k
        h = ((h << 27) | (h >> 37)) & 0xFFFFFFFFFFFFFFFF
        h = (h * 5 + 0x52DCE729) & 0xFFFFFFFFFFFFFFFF
    tail = b[n:]
    k = 0
    for i, c in enumerate(reversed(tail)):
        k |= c << (8 * (len(tail) - 1 - i))
    if tail:
        k = (k * 0x87ED55B7DAA19B63) & 0xFFFFFFFFFFFFFFFF
        k = ((k << 31) | (k >> 33)) & 0xFFFFFFFFFFFFFFFF
        k = (k * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        h ^= k
    h ^= len(b)
    h ^= h >> 33
    h = (h * 0xFF51AFD7ED558CCD) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    h = (h * 0xC4CEB9FE1A85EC53) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    return h


FUNCS = {
    "fnv1a64": fnv1a64, "fnv1_64": fnv1_64, "djb2": djb2, "sdbm": sdbm,
    "murmur3_64": murmur3_64,
    "md5_lo": lambda b: struct.unpack("<Q", hashlib.md5(b).digest()[:8])[0],
    "md5_hi": lambda b: struct.unpack("<Q", hashlib.md5(b).digest()[8:])[0],
    "sha1_lo": lambda b: struct.unpack("<Q", hashlib.sha1(b).digest()[:8])[0],
    "jhash32": lambda b: jstr(b),
}

targets = {c for c, _ in ARMS}
print("arm constants: %d" % len(targets))
hits = 0
for fname, fn in FUNCS.items():
    for k in KEYS:
        v = fn(k.encode()) & 0xFFFFFFFFFFFFFFFF
        if v in targets:
            arm = [hex(t) for c, t in ARMS if c == v][0]
            print("HIT %-10s %-28s = 0x%016x  arm->%s" % (fname, k, v, arm))
            hits += 1
print("total hits: %d" % hits)
