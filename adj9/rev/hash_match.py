# hash_match.py - extract the 64-bit case constants from nsign_fn.log and match them
# against hashes of the known map keys. The nSign field switch compares a per-key
# 64-bit tag in x8/x10 against inline constants; the tag is almost certainly a
# hash of the map key string. Match => arm->key mapping => per-key writer bodies.
import hashlib
import re
import sys
import zlib

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))

regs = {}


def regval(r):
    return regs.get(r, 0)


def setmov(dst, v, sh, kind):
    cur = regs.get(dst, 0)
    if kind in ("mov", "movz"):
        cur = 0
    if kind == "movn":
        cur = (v << sh) ^ 0xFFFFFFFFFFFFFFFF
        regs[dst] = cur & 0xFFFFFFFFFFFFFFFF
        return
    mask = ~(0xFFFF << sh) & 0xFFFFFFFFFFFFFFFF
    regs[dst] = ((cur & mask) | ((v & 0xFFFF) << sh)) & 0xFFFFFFFFFFFFFFFF


consts = []  # (cmp_addr, reg, value)
for a, m, o in ins:
    mm = re.match(r"(x\d+|w\d+|xzr|wzr),\s*#(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?", o)
    if m in ("mov", "movz", "movn", "movk") and mm:
        r, v, sh = mm.group(1), int(mm.group(2), 16), int(mm.group(3) or 0)
        setmov(r, v, sh, m)
    elif m in ("cmp", "ccmp"):
        parts = [p.strip() for p in o.split(",")]
        if len(parts) >= 2 and re.match(r"x\d+$", parts[1]):
            consts.append((a, parts[1], regval(parts[1])))
        regs = {}

print("cmp-with-reg consts:", len(consts))
uniq = {}
for a, r, v in consts:
    uniq.setdefault(v, []).append(a)
print("unique values:", len(uniq))
for v, addrs in sorted(uniq.items()):
    print("  %016x  at %s" % (v, ",".join("0x%x" % a for a in addrs[:6])))

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
        "adj_verification", "algorithm", "app_version_code", "referrer"]


def fnv1a64(s):
    h = 0xCBF29CE484222325
    for c in s.encode():
        h ^= c
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def djb2_64(s):
    h = 5381
    for c in s.encode():
        h = ((h * 33) + c) & 0xFFFFFFFFFFFFFFFF
    return h


def sdbm(s):
    h = 0
    for c in s.encode():
        h = (c + (h << 6) + (h << 16) - h) & 0xFFFFFFFFFFFFFFFF
    return h


FUNCS = {
    "fnv1a64": fnv1a64,
    "djb2_64": djb2_64,
    "sdbm64": sdbm,
    "md5lo": lambda s: int.from_bytes(hashlib.md5(s.encode()).digest()[:8], "little"),
    "md5hi": lambda s: int.from_bytes(hashlib.md5(s.encode()).digest()[8:], "little"),
    "sha1lo": lambda s: int.from_bytes(hashlib.sha1(s.encode()).digest()[:8], "little"),
    "crccat": lambda s: (zlib.crc32(s.encode()) & 0xFFFFFFFF) | ((len(s) & 0xFFFFFFFF) << 32),
}
TSET = set(uniq.keys())
print("\n=== hash matches ===")
hits = 0
for fname, fn in FUNCS.items():
    for k in KEYS:
        try:
            v = fn(k) & 0xFFFFFFFFFFFFFFFF
        except Exception:
            continue
        if v in TSET:
            print("  %-8s %-28s = %016x  (arms %s)" % (
                fname, k, v, ",".join("0x%x" % a for a in uniq[v][:4])))
            hits += 1
print("total hits:", hits)
print("done")