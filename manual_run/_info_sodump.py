"""_info_sodump.py -- locate the claims key strings inside penti_libsigner.so
(each string obfuscated with its own single-byte XOR key), and dump the string
neighbourhoods to recover the per-kind claims key lists.
"""
import re, sys

D = open(r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea"
         r"\sdk_diff\libs\penti_libsigner.so", "rb").read()

NEEDLES = [b"adj_verification", b"android_uuid", b"api_level", b"app_token",
           b"app_version", b"country", b"created_at", b"device_name",
           b"device_type", b"environment", b"gps_adid", b"gps_adid_src",
           b"hardware_name", b"installed_at", b"os_build", b"os_name",
           b"os_version", b"package_name", b"push_token",
           b"first_error", b"last_error", b"offline_mode_enabled",
           b"retry_count", b"source", b"wait_time", b"wait_total",
           b"tracking_enabled", b"sent_at", b"foreground",
           b"needs_response_details", b"attribution_deeplink",
           b"enqueue_size", b"gps_adid_attempt",
           b"session_count", b"session_length", b"store_name_from_system",
           b"subsession_count", b"time_spent", b"updated_at",
           b"activity_kind", b"client_sdk", b"headers_id", b"native_version",
           b"adj_signing_id", b"initiated_by", b"seq", b"event_count",
           b"event_token", b"partner_params", b"click_time", b"referrer",
           b"initiating_package_name", b"google_play_instant"]

hits = {}
for n in NEEDLES:
    found = []
    for k in range(1, 256):
        t = bytes(b ^ k for b in n)
        i = 0
        while True:
            i = D.find(t, i)
            if i < 0:
                break
            found.append((i, k))
            i += 1
    hits[n] = sorted(set(found))

def decode_run(i, k, maxn=64):
    """decode a NUL-terminated string starting at i with key k"""
    out = bytearray()
    for j in range(i, min(i + maxn, len(D))):
        c = D[j] ^ k
        if c == 0:
            break
        out.append(c)
    return bytes(out)

def try_decode_string_at(i):
    """the byte at i is the first byte of an obfuscated string; try all keys,
    return the (k, s) with the most plausible key-name look"""
    best = None
    for k in range(1, 256):
        s = decode_run(i, k)
        if not s or len(s) < 3:
            continue
        try:
            t = s.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not re.fullmatch(r"[a-z0-9_.\-${}/]+", t):
            continue
        score = len(t)
        if best is None or score > best[2]:
            best = (k, t, score)
    return best

allh = sorted((i, n.decode(), k) for n, fs in hits.items() for i, k in fs)
print("total key-name hits:", len(allh))
for i, n, k in allh:
    print("%#08x key=%02x %s" % (i, k, n))

def decode_with_key(i, k, maxn=80):
    out = bytearray()
    for j in range(i, min(i + maxn, len(D))):
        c = D[j] ^ k
        if c == 0:
            return bytes(out)
        if not (0x20 <= c < 0x7f):
            return None
        out.append(c)
    return bytes(out)

# For every hit, decode the string that STARTS at (or before) the hit using its
# own key, then also decode the NEXT strings: walk forward from the hit's string
# end, trying only the keys observed so far in this region.
keys_seen = sorted(set(k for _, _, k in allh))
print("keys seen:", [hex(k) for k in keys_seen])

if allh:
    lo = max(0, min(i for i, _, _ in allh) - 800)
    hi = min(len(D), max(i for i, _, _ in allh) + 2500)
    print("---- region %#x..%#x ----" % (lo, hi))
    i = lo
    out = []
    while i < hi:
        best = None
        for k in keys_seen:
            s = decode_with_key(i, k)
            if s and len(s) >= 3 and re.fullmatch(r"[a-zA-Z0-9_.\-/$]{3,}", s.decode()):
                if best is None or len(s) > len(best[1]):
                    best = (k, s.decode())
        if best:
            out.append((i, best[0], best[1]))
            i += len(best[1]) + 1
        else:
            i += 1
    for i, k, s in out:
        print("%#08x k=%02x %r" % (i, k, s))
    import json
    json.dump([[i, k, s] for i, k, s in out],
              open(r"C:\Users\Apps\Downloads\com.penti.app\manual_run\_info_so_strings.json", "w"))
