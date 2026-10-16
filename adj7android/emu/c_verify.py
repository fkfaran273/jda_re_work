# Verify candidate cipher law against trace4 states at round boundaries.
# Candidate:
#   init: ST = record ^ IV  (byte-for-byte)
#   pass per block b (16 passes over blocks 0..15, in order):
#     round 1:  ST[16b+1+i] ^= key[i] ^ 0x55   for i in 0..14   (no ST[16b])
#     round r (2..11): ST[16b+i] ^= key[15+16(r-2)+i] ^ 0x55 for i in 0..15
#     each round after ARK: SB (std AES), SR (row rotate), MC (std AES)
#     (final round maybe without MC -- tested)
import gzip

KEYLO, STLO = 0x900e3e8, 0x900e6e8
SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
KEY = bytes.fromhex(
 "20ff2ce6100d3d3f18397e2ee95cd1cb254fb30fa132afc29bb9dfd7d157e47b"
 "57373fc8126f57a25f037cd9e30af8af6b8026f59fe7dc62510b56e0d509e7be"
 "1d00ea235a3ae8d4506cc158e6336c7806b334d8cc01bdefc85fbe5a48030c0a"
 "accb9c7ca3a421fda69db5f015fb8c7e0f5701f39603e9490b090246165f5b30"
 "cb60e1193d9195b1ce5975148ef7acfdb66d985b753b24472b677354686d7d57"
 "cc549d1ba4905dff3f9c7dbee43e84")   # 175 bytes; byte 175 unknown (junk)

IV = bytes.fromhex("40e0f7831ec4508f5085436f0de0bc39")
C0 = bytes.fromhex("4da745a0be7da89170af6e32246cd7d6")


def xt(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xt(a)
        b >>= 1
    return p


def mc_col(c):
    return bytes([
        gmul(c[0], 2) ^ gmul(c[1], 3) ^ c[2] ^ c[3],
        c[0] ^ gmul(c[1], 2) ^ gmul(c[2], 3) ^ c[3],
        c[0] ^ c[1] ^ gmul(c[2], 2) ^ gmul(c[3], 3),
        gmul(c[0], 3) ^ c[1] ^ c[2] ^ gmul(c[3], 2)])


def sb(s):
    return bytes(SBOX[b] for b in s)


def sr(s):
    # row-major 4x4: row r rotated left by r
    o = list(s)
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            o[4 * c + r] = row[c]
    return bytes(o)


def mc(s):
    return b"".join(mc_col(s[4 * i:4 * i + 4]) for i in range(4))


# --- load ST write log ---
stw = []   # (evi, idx, val)
krd = []
with gzip.open("trace4.txt.gz", "rt") as f:
    for line in f:
        p = line.split()
        w = p[0] == "W"
        a = int(p[2], 16)
        s = int(p[3])
        v = int(p[4], 16) & ((1 << (s * 8)) - 1)
        if s != 4:
            continue
        if KEYLO <= a < KEYLO + 768 and not w:
            krd.append(((a - KEYLO) // 4, v))
        elif STLO <= a < STLO + 1024 and w:
            stw.append(((a - STLO) // 4, v))
print("ST writes:", len(stw), "key reads:", len(krd))

# --- replay state; find snapshots right before each ARK group ---
st = [None] * 256
k_i = 0
# key-read groups (gap by index in krd order using stw positions is hard;
# instead group krd by slot runs: setup(191,175..190), then rounds)
# We reconstruct by walking stw and krd in event order -- but we lost evi for
# krd. Redo: walk the file once keeping both with evi.

stw2 = []
krd2 = []
evi = 0
with gzip.open("trace4.txt.gz", "rt") as f:
    for line in f:
        p = line.split()
        w = p[0] == "W"
        a = int(p[2], 16)
        s = int(p[3])
        v = int(p[4], 16) & ((1 << (s * 8)) - 1)
        if s == 4:
            if KEYLO <= a < KEYLO + 768 and not w:
                krd2.append((evi, (a - KEYLO) // 4, v))
            elif STLO <= a < STLO + 1024 and w:
                stw2.append((evi, (a - STLO) // 4, v))
        evi += 1

# group key reads by slot-runs with gap detection on evi
groups = []
cur = [krd2[0]]
for item in krd2[1:]:
    if item[0] - cur[-1][0] > 4000:
        groups.append(cur)
        cur = [item]
    else:
        cur.append(item)
groups.append(cur)
print("key groups:", [(g[0][1], g[-1][1]) for g in groups])

# state snapshot function: apply stw2 writes up to evi
def state_at(evi_limit):
    st = [None] * 256
    for e, idx, v in stw2:
        if e > evi_limit:
            break
        st[idx] = v
    return st

# verify round r of block 0 (pass 1): pre-state before group g's first key
# read; candidate ARK+SB+SR+MC == pre-state of group g+1?
for gi in range(1, len(groups) - 1):
    g = groups[gi]
    nxt = groups[gi + 1]
    if g[0][1] > 174:
        continue
    pre = state_at(g[0][0] - 1)
    post = state_at(nxt[0][0] - 1)
    slots = [slot for _, slot, _ in g]
    blk = 0
    # candidate transform
    s = list(pre)
    if gi == 1:
        for i, slot in enumerate(slots):
            s[blk * 16 + 1 + i] ^= KEY[slot] ^ 0x55
    else:
        for i, slot in enumerate(slots):
            s[blk * 16 + i] ^= KEY[slot] ^ 0x55
    b = s[0:16]
    b = sb(b)
    b = sr(b)
    b = mc(b)
    ok = (list(b) == post[0:16])
    print("group %d slots %d..%d: candidate(SB+SR+MC) match=%s" %
          (gi, slots[0], slots[-1], ok))
    if not ok:
        # try without MC
        b2 = sr(sb(bytes(s[0:16])))
        print("   without MC match=%s" % (list(b2) == post[0:16]))
        print("   traced post:", bytes(x or 0 for x in post[0:16]).hex())
        print("   cand  SB+SR:", b2.hex())
        print("   cand  full :", b.hex())
