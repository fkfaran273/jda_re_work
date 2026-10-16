# Localize divergence: simulate stage-by-stage vs traced group-start states.
import gzip

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
 "cc549d1ba4905dff3f9c7dbee43e84")
PRE = [bytes.fromhex(h) for h in (
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


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# traced events
STLO, KEYLO = 0x900e6e8, 0x900e3e8
evs = []   # (evi, kind, idx, val)
with gzip.open("trace4.txt.gz", "rt") as f:
    evi = 0
    for line in f:
        p = line.split()
        a = int(p[2], 16)
        if int(p[3]) == 4:
            if p[0] == "W" and STLO <= a < STLO + 1024:
                evs.append((evi, "W", (a - STLO) // 4,
                            int(p[4], 16) & 0xFF))
            elif p[0] == "R" and KEYLO <= a < KEYLO + 768:
                evs.append((evi, "K", (a - KEYLO) // 4,
                            int(p[4], 16) & 0xFF))
        evi += 1
        if evi > 2900000:
            break

kgroups = []
cur = None
for e, kind, idx, v in evs:
    if kind == "K":
        if cur is None or e - cur[-1][0] > 4000:
            cur = []
            kgroups.append(cur)
        cur.append((e, idx, v))
gstarts = [g[0][0] for g in kgroups]
print("group starts:", gstarts)


def traced_state_at(limit):
    st = [None] * 16
    for e, kind, idx, v in evs:
        if e >= limit:
            break
        if kind == "W" and idx < 16:
            st[idx] = v
    return st


# simulate
s = bytes.fromhex("3bc0d5e23cfe70af70bd705a3cd88c0d")
stages = []
for i, c in enumerate(PRE):
    s = xor(s, c)
    stages.append(("pre%d-ark" % (i + 1), bytes(s)))
    s = mc(sr(sb(s)))
    stages.append(("pre%d-mix" % (i + 1), bytes(s)))
stages.append(("->g1", bytes(s)))


def check(name, target_ev):
    t = traced_state_at(target_ev)
    tb = bytes(x if x is not None else 0 for x in t)
    ok = tb == s
    print("%-12s sim=%s traced=%s %s" %
          (name, s.hex(), tb.hex(), "OK" if ok else "<<< DIVERGE"))
    return ok


# at group1 start state should equal post pre-rounds
t = traced_state_at(gstarts[1])
print("pre-rounds end: sim=%s traced=%s %s" %
      (s.hex(), bytes(x or 0 for x in t).hex(),
       bytes(x or 0 for x in t) == s))

# round 1
s = bytes([s[0]]) + xor(s[1:], bytes(b ^ 0x55 for b in KEY[0:15]))
s = mc(sr(sb(s)))
t = traced_state_at(gstarts[2])
print("round1 end:    sim=%s traced=%s %s" %
      (s.hex(), bytes(x or 0 for x in t).hex(),
       bytes(x or 0 for x in t) == s))

for r in range(2, 11):
    off = 15 + 16 * (r - 2)
    s = xor(s, bytes(b ^ 0x55 for b in KEY[off:off + 16]))
    if r < 10:
        s = mc(sr(sb(s)))
    else:
        s = sr(sb(s))
    t = traced_state_at(gstarts[r + 1])
    print("round%d end:   sim=%s traced=%s %s" %
          (r, s.hex(), bytes(x or 0 for x in t).hex(),
           bytes(x or 0 for x in t) == s))
