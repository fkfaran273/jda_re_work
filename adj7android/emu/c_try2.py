# Full SPN simulator + verification against trace4 states (block 0 & 1).
import gzip, itertools

SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
INV = [0] * 256
for i, v in enumerate(SBOX):
    INV[v] = i
KEY = bytes.fromhex(
 "20ff2ce6100d3d3f18397e2ee95cd1cb254fb30fa132afc29bb9dfd7d157e47b"
 "57373fc8126f57a25f037cd9e30af8af6b8026f59fe7dc62510b56e0d509e7be"
 "1d00ea235a3ae8d4506cc158e6336c7806b334d8cc01bdefc85fbe5a48030c0a"
 "accb9c7ca3a421fda69db5f015fb8c7e0f5701f39603e9490b090246165f5b30"
 "cb60e1193d9195b1ce5975148ef7acfdb66d985b753b24472b677354686d7d57"
 "cc549d1ba4905dff3f9c7dbee43e84")
IV0 = bytes.fromhex("40e0f7831ec4508f5085436f0de0bc39")
PREK = [bytes.fromhex(h) for h in (
    "f110fb41676dba311f38c652c8f951ec",
    "3db456c07b9166a509bef66cd870654b",
    "a15d4820c630f211d908344311f165af",
    "bf151bb9c4847d1ccd3a8b70154aee3b")]


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
    o = list(s)
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            o[4 * c + r] = row[c]
    return bytes(o)


def mc(s):
    return b"".join(mc_col(s[4 * i:4 * i + 4]) for i in range(4))


def ark(s, k, off=0, n=16, dst=0):
    o = bytearray(s)
    for i in range(n):
        o[dst + i] ^= k[off + i]
    return bytes(o)


def block_crypt(x, final="sb_sr"):
    s = bytes(x)
    for c in PREK:                       # 4 pre-rounds
        s = ark(s, c)
        s = mc(sr(sb(s)))
    # 11 keyed rounds
    s = ark(s, KEY, 0, 15, 1)            # round1: ST[1..15], key[0..14]
    s = mc(sr(sb(s)))
    for r in range(2, 11):               # rounds 2..10
        s = ark(s, KEY, 15 + 16 * (r - 2))
        if r < 10:
            s = mc(sr(sb(s)))
        else:
            s = sr(sb(s))                # round 10: no MC
    s = ark(s, KEY, 159)                 # round 11
    if final == "sb_sr":
        s = sr(sb(s))
    elif final == "sb":
        s = sb(s)
    elif final == "sr":
        s = sr(s)
    elif final == "none":
        pass
    return s


# ---- load traced states ----
STLO, KEYLO = 0x900e6e8, 0x900e3e8
stw, krd = [], []
evi = 0
with gzip.open("trace4.txt.gz", "rt") as f:
    for line in f:
        p = line.split()
        w = p[0] == "W"
        a = int(p[2], 16)
        s_ = int(p[3])
        v = int(p[4], 16) & ((1 << (s_ * 8)) - 1)
        if s_ == 4:
            if KEYLO <= a < KEYLO + 768 and not w:
                krd.append((evi, (a - KEYLO) // 4))
            elif STLO <= a < STLO + 1024 and w:
                stw.append((evi, (a - STLO) // 4, v))
        evi += 1

groups = []
cur = [krd[0]]
for item in krd[1:]:
    if item[0] - cur[-1][0] > 4000:
        groups.append(cur)
        cur = [item]
    else:
        cur.append(item)
groups.append(cur)
iv_gi = [i for i, g in enumerate(groups) if g[0][1] == 175][0]
g1 = groups[1][0][0]
g2 = groups[iv_gi + 1][0][0]   # pass2 round1 start


def state_at(evi_limit, base=0):
    st = [None] * 16
    for e, idx, v in stw:
        if e > evi_limit:
            break
        if base <= idx < base + 16:
            st[idx - base] = v
    return st


# block 0: init writes (record^IV) then final pre-round-1 state
init0 = state_at(groups[1][0][0] - 1, 0)      # just before round1 ARK
C0t = bytes.fromhex("4da745a0be7da89170af6e32246cd7d6")
# find init state: the state right after the LAST full init write layer but
# before pre-round 1 -- approximate: state at first ST write event after the
# record load. Simpler: run the whole pipeline on record0^IV:
# record0 recovered from first 16 init writes:
first16 = []
seen = set()
for e, idx, v in stw:
    if idx < 16 and idx not in seen:
        seen.add(idx)
        first16.append((idx, v))
    if len(seen) == 16:
        break
w0 = [v for _, v in sorted(first16)]
record0 = bytes(w0[i] ^ IV0[i] for i in range(16))
print("record0:", record0, record0.hex())

for final in ("none", "sb", "sr", "sb_sr"):
    c = block_crypt(record0, final=final) if False else None
    # full: x = record0 (already ^IV via init writes) -> crypt
    got = block_crypt(bytes(w0), final=final)
    print("final=%-6s -> %s  (target %s)  %s" %
          (final, got.hex(), C0t.hex(), "MATCH" if got == C0t else ""))
