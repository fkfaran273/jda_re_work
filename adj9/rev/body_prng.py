# body_prng.py — rows 4 and 5 of the run7 rapid fire share seed 1788956310,
# so they share the ENTIRE bionic random() stream.  Their headers are equal; their
# 176B bodies differ completely.  Question: is the body drawn from that SAME stream
# at some (possibly varying) offset, or from somewhere else entirely?
#
# Templates tested for each 32-bit BE word of the blob:
#   T1  w = d[k]                      (single draw, 31-bit)
#   T2  w = d[k] ^ d[k+1]             (the header template)
#   T3  w = d[k] ^ d[k+1] ^ d[k+2]
#   T4  w = (d[k] + d[k+1]) mod 2^32
#   T5  w = d[k] * 2  /  d[k] | 0x80000000
#   T6  w = (d[k] << 1) ^ d[k+1]
# and the same for BYTE streams: b = d[k]&0xff, b = (d[k]^d[k+1])&0xff, (d[k]>>8)&0xff ...
import struct
from header_gen import Random3

SEED = 1788956310
b4 = bytes.fromhex(
 "49672b213dde2d9d11aad13516394cf7587be4864fc1ee8ff931ed7d47dc4e30a1278565cc6fcf1fced296a689fb2f6a0820f2fb3d3e0d3116b24445057e5d18ca0261747980a4ea6819522072ae8b0bff3df71731ca1752aef5c057faebb7da6bc8f545ee250b25b2693223c3266b5caf4d497ae9aa5a594a8ca05175c2c91269f713fa7d87410f945960e73f53c9761793836af69fdd715d0c0a0e2b2ddfe610ca6f8f04c8082c597e34eae53e3d4bdff68b880ebcb40e9702b2b5e0042f19")
b5 = bytes.fromhex(
 "49672b213dde2d9d11aad13516394cf7bf75c9175c81cfaeb6210c85fc27b6593b0ba7437d141eab4c305d9135711f52a3063f94a0afc88e48b56e3b4dde0d1c1d2dc3c6233fcb1c85ff972b31a8cb054f1ba52f2d2833e27bf7aaf5993473f9d983cb763827195be9d98b45e454323cb4548049cb1fef42a7a5dc37ac1ac6ffb3995e33d6c26e3701c813a8a02adcd2807a861b6a0900dd7ee4c4c0ee9022c7d62a919be7fa70c217816550713acf5906bbea6a1545b2429ec21c15d3fbcb59")
assert len(b4) == len(b5) == 192 and b4[:16] == b5[:16]

N = 60000
R = Random3(SEED)
d = [R.next() for _ in range(N)]
print("generated %d draws from seed %d" % (N, SEED))

def words(b, off=0, n=None):
    n = n if n is not None else (len(b) - off) // 4
    return [struct.unpack_from(">I", b, off + 4 * i)[0] for i in range(n)]

hw = words(b4, 0, 4)
print("header words:", [hex(x) for x in hw])
# sanity: T2 at offset 0
print("T2 k=0..3 gives:", [hex(d[2 * i] ^ d[2 * i + 1]) for i in range(4)],
      "=> header template confirmed" if [d[2 * i] ^ d[2 * i + 1] for i in range(4)] == hw else "MISMATCH")

tmpl = {
    "T1 d[k]":        lambda k: d[k],
    "T2 d[k]^d[k+1]": lambda k: d[k] ^ d[k + 1],
    "T3 3-xor":       lambda k: d[k] ^ d[k + 1] ^ d[k + 2],
    "T4 sum":         lambda k: (d[k] + d[k + 1]) & 0xFFFFFFFF,
    "T5 d[k]<<1|hi":  lambda k: ((d[k] << 1) | (d[k] >> 30)) & 0xFFFFFFFF,
    "T6 (d[k]<<1)^d[k+1]": lambda k: ((d[k] << 1) ^ d[k + 1]) & 0xFFFFFFFF,
}

for name, f in tmpl.items():
    idx = {}
    for k in range(N - 3):
        idx.setdefault(f(k), k)
    for tag, blob in (("row4", b4), ("row5", b5)):
        bw = words(blob, 16)           # 44 body words
        hits = [(i, idx.get(w)) for i, w in enumerate(bw) if w in idx]
        print("  %-22s %s body words matched: %d/44  first few (wordidx->draw): %s"
              % (name, tag, len(hits), hits[:5]))

# byte-level: is the body just low bytes of the stream?
print("\nbyte-level templates (176 body bytes):")
low1 = [x & 0xFF for x in d]
low2 = [(x >> 8) & 0xFF for x in d]
low3 = [(x >> 16) & 0xFF for x in d]
xorlow = [(d[k] ^ d[k + 1]) & 0xFF for k in range(N - 1)]
for nm, seq in (("d[k]&0xff", low1), ("(d[k]>>8)&0xff", low2),
                ("(d[k]>>16)&0xff", low3), ("(d[k]^d[k+1])&0xff", xorlow)):
    s = set(seq)
    c4 = sum(1 for x in b4[16:] if x in s)
    print("  %-20s distinct values %3d ; row4 body bytes in set: %d/176" % (nm, len(s), c4))

# does the body look like it starts at a fixed draw offset in EITHER row?
print("\nlongest run of body words found contiguously in the stream (T2 template):")
for tag, blob in (("row4", b4), ("row5", b5)):
    bw = words(blob, 16)
    idx = {}
    for k in range(N - 3):
        idx.setdefault(d[k] ^ d[k + 1], k)
    pos = [idx.get(w, -1) for w in bw]
    print("  %s draw offsets: %s" % (tag, pos[:12]))
