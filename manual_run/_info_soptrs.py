"""_info_soptrs.py -- recover the per-kind claims key LISTS from
penti_libsigner.so: find the string pointers into the key-name region and the
consecutive pointer arrays that reference them, in order.
"""
import struct, json, sys

PATH = (r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea"
        r"\sdk_diff\libs\penti_libsigner.so")
D = open(PATH, "rb").read()

# ---- ELF64 program headers: file offset <-> vaddr ----
assert D[:4] == b"\x7fELF"
is64 = D[4] == 2
e_phoff = struct.unpack_from("<Q", D, 0x20)[0]
e_phentsize = struct.unpack_from("<H", D, 0x36)[0]
e_phnum = struct.unpack_from("<H", D, 0x38)[0]
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", D, off)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", D, off + 8)
    if p_type == 1:  # PT_LOAD
        segs.append((p_offset, p_vaddr, p_filesz))
print("PT_LOAD segs:", [(hex(a), hex(b), hex(c)) for a, b, c in segs])

def off2va(o):
    for p_offset, p_vaddr, p_filesz in segs:
        if p_offset <= o < p_offset + p_filesz:
            return p_vaddr + (o - p_offset)
    return None

def va2off(v):
    for p_offset, p_vaddr, p_filesz in segs:
        if p_vaddr <= v < p_vaddr + p_filesz:
            return p_offset + (v - p_vaddr)
    return None

# ---- decode the key-name strings (each with its own XOR key = terminator byte)
# We know many (start, key) pairs from the needle scan; decode each string
# starting at i with key k until the terminator byte (== k).
def decode_str(i, k, maxn=96):
    out = bytearray()
    for j in range(i, min(i + maxn, len(D))):
        c = D[j] ^ k
        if c == 0:
            return bytes(out), j
        out.append(c)
    return None, None

# rebuild the needle scan (fast find version)
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
           b"initiating_package_name", b"google_play_instant",
           b"click_time_server", b"install_begin_time",
           b"install_begin_time_server", b"install_version", b"referrer_api",
           b"event_callback_id", b"purchase_time", b"currency", b"revenue"]

strings = {}   # va -> decoded name
for n in NEEDLES:
    for k in range(1, 256):
        t = bytes(b ^ k for b in n)
        i = 0
        while True:
            i = D.find(t, i)
            if i < 0:
                break
            s, term = decode_str(i, k)
            if s == n:
                va = off2va(i)
                if va is not None:
                    strings[va] = n.decode()
            i += 1

print("decoded %d key strings" % len(strings))
vas = sorted(strings)

# ---- find pointer arrays: consecutive VA words pointing into the string set
# scan the whole file for little-endian 32/64-bit words equal to a string VA
ptr_hits = {}   # file offset -> va
sset = set(vas)
step = 8 if is64 else 4
for o in range(0, len(D) - step, 4):
    if is64:
        v = struct.unpack_from("<Q", D, o)[0]
    else:
        v = struct.unpack_from("<I", D, o)[0]
    if v in sset:
        ptr_hits[o] = v
print("pointer hits:", len(ptr_hits))

# group consecutive hits (stride = pointer size) into arrays
offs = sorted(ptr_hits)
arrays = []
cur = [offs[0]] if offs else []
for a, b in zip(offs, offs[1:]):
    if b - a == step:
        cur.append(b)
    else:
        if len(cur) >= 3:
            arrays.append(cur)
        cur = [b]
if len(cur) >= 3:
    arrays.append(cur)

print("\n==== pointer arrays (%d) ====" % len(arrays))
out = []
for arr in arrays:
    names = [strings[ptr_hits[o]] for o in arr]
    va0 = off2va(arr[0])
    print("array @ va %#x (off %#x), %d ptrs:" % (va0, arr[0], len(arr)))
    print("   ", names)
    out.append({"va": va0, "off": arr[0], "names": names})
json.dump(out, open(r"C:\Users\Apps\Downloads\com.penti.app\manual_run\_info_so_arrays.json", "w"), indent=1)
