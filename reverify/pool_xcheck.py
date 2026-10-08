"""Independent re-verification of the claim-pool string table in
apks/in.hanafintech_libsigner.so (3.62.0 Adjust signature lib).

Prior claim: a string table at file offset 0x1169b0 holds claim-key
strings XOR-masked with byte 0x16, NUL-terminated, contiguous.

This script does NOT trust that offset: it searches the WHOLE file for
the XOR-0x16 encodings of b"activity_kind", b"session_count",
b"gps_adid", then expands from the earliest hit to the exact boundaries
of the contiguous XOR-0x16 printable region and decodes it.

Empirical format found (v2 of this script): the region is ONE
XOR-0x16-masked, comma-separated key list whose NUL terminator is
itself masked (file byte 0x16 -> decoded 0x00), not a run of
individually NUL-terminated strings.  Keys are recovered by splitting
the decoded blob on ','.
"""
import re
import sys

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\reverify")
from verify_from_scratch import CLAIM_POOL

SO = (r"C:\Users\Apps\Downloads\com.penti.app"
      r"\reverify\apks\in.hanafintech_libsigner.so")
OUT = (r"C:\Users\Apps\Downloads\com.penti.app"
       r"\reverify\findings\pool_strings.txt")

data = open(SO, "rb").read()
print("file: %s\nsize: %d bytes" % (SO, len(data)))


def xor16(b):
    return bytes(x ^ 0x16 for x in b)


# -- 1. whole-file needle search --------------------------------------
needles = [b"activity_kind", b"session_count", b"gps_adid"]
all_hits = []
for n in needles:
    enc = xor16(n)
    offs = []
    i = data.find(enc)
    while i >= 0:
        offs.append(i)
        i = data.find(enc, i + 1)
    print("needle %-14s xor16 hits: %s" % (n.decode(),
                                           [hex(o) for o in offs]))
    all_hits += offs
if not all_hits:
    sys.exit("no hits -- table not found")
first = min(all_hits)
print("earliest hit: 0x%x" % first)

# -- 2. expand to exact contiguous XOR-0x16 printable blob -------------
def printable(b):
    return 0x20 <= (b ^ 0x16) <= 0x7E


start = first
while start > 0 and printable(data[start - 1]):
    start -= 1
end = first
while end < len(data) and printable(data[end]):
    end += 1
term = data[end] ^ 0x16 if end < len(data) else None
print("contiguous XOR-0x16 printable blob: 0x%x .. 0x%x (len %d)"
      % (start, end, end - start))
print("claimed table start 0x1169b0 -> %s"
      % ("MATCH" if start == 0x1169b0 else "DIFFERENT"))
print("byte after blob: 0x%02x (decoded 0x%02x) -> %s"
      % (data[end], term,
         "masked NUL terminator" if term == 0 else "NOT a NUL"))

blob = bytes(b ^ 0x16 for b in data[start:end])
text = blob.decode("ascii")

# -- 3. split, dump, compare -------------------------------------------
keys = text.split(",")
with open(OUT, "w") as f:
    f.write("\n".join(keys) + "\n")
print("decoded %d comma-separated strings -> %s" % (len(keys), OUT))

pool = list(CLAIM_POOL)
pool_set = set(pool)
bin_set = set(keys)
missing = [k for k in pool if k not in bin_set]
snake = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*$")
extra = [k for k in keys if snake.match(k) and k not in pool_set]
nonsnake = [k for k in keys if not snake.match(k)]
dupes = sorted({k for k in keys if keys.count(k) > 1})

print("\nCLAIM_POOL size: %d   decoded binary strings: %d"
      % (len(pool), len(keys)))
print("MISSING from binary (in CLAIM_POOL, not in file): %s"
      % (missing or "NONE"))
print("EXTRA snake_case in file (not in CLAIM_POOL): %s"
      % (extra or "NONE"))
print("non-snake_case strings in region: %s" % (nonsnake or "NONE"))
print("duplicated strings in region: %s" % (dupes or "NONE"))

tail_ok = len(keys) >= 2 and keys[-2:] == ["activity_kind", "client_sdk"]
core = keys[:-2] if tail_ok else keys
alpha = core == sorted(core)
same_order = core == pool[:-2]
print("tail == [activity_kind, client_sdk]: %s" % tail_ok)
print("core (first %d) alphabetical: %s" % (len(core), alpha))
print("core order identical to CLAIM_POOL core: %s" % same_order)
if not alpha:
    for i, (a, b) in enumerate(zip(core, sorted(core))):
        if a != b:
            print("  first order diff at [%d]: bin=%r vs sorted=%r"
                  % (i, a, b))
            break
print("\nfirst 3: %s" % keys[:3])
print("last 3:  %s" % keys[-3:])
