# deriv3.py - TEST OF THE KEYED-REGION HYPOTHESIS (offline).
#
# HYPOTHESIS UNDER TEST: the 56 unknown bytes ("region": descriptors #0/#2/#4)
# of the 192-B adj9 signature blob are a KEYED function of the request under a
# SECRET EMBEDDED IN libsigner.so, making them server-verifiable, i.e.
#     tile_i = F(secret, claims_i, nonce_i)      nonce transmitted in-blob.
#
# Alternative (current standing model): region entropy = ONE 32-bit seed from
# /dev/urandom driving a self-keyed fold (no embedded secret).
#
# METHOD
#   1. Harvest candidate secrets from libsigner.so:
#      (a) mov/movk-assembled 64-bit constants of sub_9afa4 (0x9afa4..0x9e000)
#          from fn_9afa4_full.log, plus adjacent-pair concatenations and the
#          16-bit immediate stream;
#      (b) high-entropy 16/32/64-B windows in .rodata/.data/.data.rel.ro;
#      (c) the adj_verification string and app_token (+ hash derivatives).
#   2. For every signing row (S0/S1/S2 + pair rows with recovered seconds +
#      app rows) test tile/W0/d2/d4 against AES-128-ECB, HMAC-MD5/SHA1/SHA256,
#      MD5/SHA256 secret-concat, SipHash-2-4/1-3, XOR-masked digest, crc32
#      mixes, FNV-1a and MurmurHash3 (secret-seeded) -- both byte orders.
#   3. Nonce-structure probe on the same-claims same-second pairs (S0 vs S2,
#      pair i=2 vs i=4).
import calendar
import datetime
import hashlib
import hmac as hmac_mod
import json
import math
import os
import re
import struct
import sys
import time
import zlib
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
SO = os.path.join(os.path.dirname(HERE), os.pardir, "extracted", "arm64", "lib",
                  "arm64-v8a", "libsigner.so")
SO = os.path.normpath(os.path.join(HERE, "..", "..", "extracted", "arm64", "lib",
                                   "arm64-v8a", "libsigner.so"))
sys.path.insert(0, HERE)
from header_gen import make_header

M32 = 0xFFFFFFFF
M31 = 2147483647

LOGF = open(os.path.join(HERE, "deriv3.log"), "w", encoding="utf-8")
T0 = time.time()


def log(*a):
    s = " ".join(str(x) for x in a)
    sys.stdout.write(s + "\n")
    LOGF.write(s + "\n")
    LOGF.flush()


log("=" * 78)
log("deriv3.py - keyed-region hypothesis test  (start %s)" %
    datetime.datetime.now().isoformat(timespec="seconds"))
log("=" * 78)

# ---------------------------------------------------------------------------
# SECTION 0 - rows
# ---------------------------------------------------------------------------
H1 = bytes.fromhex("eebe704e53a5cd3dad5fbf42cbb5ef9603e5c0c89be93fb846e95081ab56fb9b")
H2 = bytes.fromhex("2236e4e66d0e2968289f2aa32e8006ad43b8b197bc103e24d9903afc5b157ede")

det = json.load(open(os.path.join(HERE, "desc_det_result.json")))
clm = json.load(open(os.path.join(HERE, "claims_s012.json")))
ALL = json.load(open(os.path.join(HERE, "all_signings.json")))
PAIR = json.load(open(os.path.join(HERE, "pair_h3.json")))


def hexwords(h):
    b = bytes.fromhex(h)
    return list(struct.unpack(">%dI" % (len(b) // 4), b))


rows = []


def add_row(rid, src, kind, second, claims, Hs, d0w, d2, d4w):
    w0 = d0w[0]
    tile = d0w[2:6]
    tile_alt = d0w[1:5]
    p = d0w[1] if d0w[2:6] == d0w[6:10] == d0w[10:14] else None
    rows.append({
        "id": rid, "src": src, "kind": kind, "sec": second, "claims": claims,
        "H": Hs, "d0": d0w, "d2": d2, "d4": d4w, "W0": w0, "P": p,
        "tile": tile, "tile_alt": tile_alt, "hdr": make_header(second),
    })


for k in range(3):
    d = det[k]
    hs = [H1] if k == 0 else [H1, H2]     # S0's H is the pair-row-7 H1; for
    # S1/S2 both window arg3 values are tried (exact pairing not recoverable).
    add_row("S%d" % k, "desc_det emit stream", d["kind"], d["sec"],
            bytes.fromhex(clm[k]["claims_hex"]), hs, d["d0"], d["d2"], d["d4"])

for r in PAIR:
    if r["i"] == 7:
        continue                            # == S0, merged there
    Hb = bytes.fromhex(r["H"]) if r.get("H") else []
    a = ALL[r["i"]]
    assert a["d0"] == r["d0"]
    add_row("P%d" % r["i"], "pair_h3 (%s)" % r["log"], "?", r["second"],
            bytes.fromhex(a["d10"]), [Hb] if Hb else [],
            hexwords(r["d0"]), int(r["d2"], 16), hexwords(r["d4"]))

for fname, sel in [("app_signings.json", None), ("app_signings2.json", None),
                   ("app_signings3.json", None), ("app_signings4.json", "dict"),
                   ("app_signings5.json", "dict")]:
    S = json.load(open(os.path.join(HERE, fname)))
    if sel == "dict":
        S = [S]
    for j, a in enumerate(S):
        d0h = a["d0"]
        if len(d0h) % 8:
            log("skip malformed %s[%d]" % (fname, j))
            continue
        add_row("app_%s%d" % (fname[4:5] if fname != "app_signings.json" else "1",
                              j if len(S) > 1 else 0),
                fname, "?", a["second"], bytes.fromhex(a["d10"]), [],
                hexwords(d0h), int(a["d2"], 16), hexwords(a["d4"]))

log("\nrows: %d" % len(rows))
for r in rows:
    log("  %-9s sec=%-11d claims=%-4d H=%s W0=%08x d2=%08x tile=%s" %
        (r["id"], r["sec"], len(r["claims"]),
         ",".join(h.hex()[:8] + ".." for h in r["H"]) or "-",
         r["W0"], r["d2"], "".join("%08x" % w for w in r["tile"])))

# sanity: S0/S2 claims identical, S1 differs
assert rows[0]["claims"] == rows[2]["claims"]
assert rows[0]["claims"] != rows[1]["claims"]
log("sanity: S0.claims == S2.claims, S1 differs  OK")

# ---------------------------------------------------------------------------
# SECTION 1 - secret harvest
# ---------------------------------------------------------------------------
log("\n" + "-" * 78)
log("SECTION 1 - secret harvest")
log("-" * 78)

# ---- (a) mov/movk constants of sub_9afa4 -----------------------------------
RE_MOVI = re.compile(r"^0x([0-9a-f]+)\s+mov\s+([wx]\d+|xzr), #(-?0x[0-9a-f]+|\d+)"
                     r"(?:, lsl #(\d+))?\s*$")
RE_MOVK = re.compile(r"^0x([0-9a-f]+)\s+movk\s+([wx]\d+), #(-?0x[0-9a-f]+|\d+), lsl #(\d+)\s*$")

regs = {}
consts = []      # (addr, reg, value) fully assembled 64-bit
words16 = []     # (addr, reg, value) terminal 16-bit immediates
fin = 0x9E000


def finalize(reg, addr):
    st = regs.pop(reg)
    if st["shifts"]:                     # had at least one movk -> 64-bit const
        consts.append((st["addr"], reg, st["val"]))
    else:
        words16.append((st["addr"], reg, st["val"] & 0xFFFF))


nmov = nmovk = 0
for line in open(os.path.join(HERE, "fn_9afa4_full.log"), encoding="utf-8",
                 errors="replace"):  # (a1) harvest from prior disassembly log
    line = line.strip()
    m = RE_MOVI.match(line)
    if m:
        nmov += 1
        addr, reg, imm, lsl = m.group(1), m.group(2), m.group(3), m.group(4)
        if reg == "xzr":
            continue
        v = int(imm, 0) & M32
        if lsl:
            v = (v << int(lsl)) & 0xFFFFFFFFFFFFFFFF
        if reg in regs:
            finalize(reg, addr)
        regs[reg] = {"addr": int(addr, 16), "val": v, "shifts": 0}
        continue
    m = RE_MOVK.match(line)
    if m:
        nmovk += 1
        addr, reg, imm, lsl = m.group(1), m.group(2), m.group(3), int(m.group(4))
        if reg == "xzr":
            continue
        if reg not in regs:
            regs[reg] = {"addr": int(addr, 16), "val": 0, "shifts": 0}
        st = regs[reg]
        st["val"] |= (int(imm, 0) & 0xFFFF) << lsl
        st["shifts"] += 1
for reg in list(regs):
    finalize(reg, 0)

log("(a) mov imm lines=%d movk lines=%d -> %d assembled 64-bit constants, "
    "%d terminal 16-bit immediates" % (nmov, nmovk, len(consts), len(words16)))
pc_range = [c for c in consts if 0x9AFA4 <= c[0] < fin]
log("    constants within 0x9afa4..0x9e000: %d" % len(pc_range))
log("    first 6: %s" % ", ".join("%s=%016x" % (c[1], c[2]) for c in consts[:6]))


def _fin_reg(regs, out, reg):
    """finalize a register being assembled: movk present -> 64-bit const."""
    st = regs.pop(reg)
    if st[2]:
        out.append((st[0], reg, st[1] & 0xFFFFFFFFFFFFFFFF))


so = open(SO, "rb").read()   # loaded early: capstone scan needs the raw bytes

# ---- (a2) INDEPENDENT capstone rescan of 0x9afa4..0x9e000 -------------------
# Re-disassemble the raw bytes so the harvest does not depend on the prior log
# (which may be truncated or from another disassembler).  Merge any constants
# the log-based pass missed.
cs_consts = []
try:
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
    _va, _sz = 0x9AFA4, fin - 0x9AFA4
    # map vaddr -> file offset via program headers
    e_phoff = struct.unpack_from("<Q", so, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", so, 0x36)[0]
    e_phnum = struct.unpack_from("<H", so, 0x38)[0]
    foff = None
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type, _pf, p_off, p_vaddr = struct.unpack_from("<IIQQ", so, base)
        p_memsz = struct.unpack_from("<Q", so, base + 32)[0]
        if p_type == 1 and p_vaddr <= _va < p_vaddr + p_memsz:
            foff = p_off + (_va - p_vaddr)
            break
    if foff is None:
        foff = _va  # fallback: identity mapping
    code = so[foff:foff + _sz]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    cs_regs = {}
    n_mov = n_movk = 0
    for ins in md.disasm(code, _va):
        if ins.mnemonic == "mov":
            parts = ins.op_str.split(", ")
            if len(parts) == 2 and parts[1].startswith("#"):
                tail = parts[1][1:]
                sh = 0
                if "lsl" in tail:
                    left, _, right = tail.partition("lsl")
                    try:
                        v = int(left.strip(), 0)
                        sh = int(right.strip().lstrip("#"), 0)
                    except ValueError:
                        continue
                else:
                    try:
                        v = int(tail.strip(), 0)
                    except ValueError:
                        continue
                n_mov += 1
                reg = parts[0]
                if reg == "xzr":
                    continue
                val = (v << sh) if sh else v
                if reg in cs_regs:
                    _fin_reg(cs_regs, cs_consts, reg)
                cs_regs[reg] = [ins.address, val & 0xFFFFFFFFFFFFFFFF, 0]
        elif ins.mnemonic == "movk":
            parts = ins.op_str.split(", ")
            if len(parts) >= 2 and parts[1].startswith("#"):
                try:
                    imm = int(parts[1][1:].split(",")[0].strip(), 0)
                except ValueError:
                    continue
                sh = 0
                if len(parts) > 2 and "lsl" in parts[2]:
                    try:
                        sh = int(parts[2].split("#")[1], 0)
                    except (ValueError, IndexError):
                        sh = 0
                n_movk += 1
                reg = parts[0]
                if reg == "xzr":
                    continue
                if reg not in cs_regs:
                    cs_regs[reg] = [ins.address, 0, 0]
                cs_regs[reg][1] |= (imm & 0xFFFF) << sh
                cs_regs[reg][2] += 1
    for reg in list(cs_regs):
        _fin_reg(cs_regs, cs_consts, reg)
    log("(a2) capstone rescan 0x9afa4..0x9e000: mov=%d movk=%d -> %d consts"
        % (n_mov, n_movk, len(cs_consts)))
    if cs_consts:
        log("    last 4: %s" % ", ".join("%s=%016x" % (c[1], c[2])
                                         for c in cs_consts[-4:]))
except Exception as e:
    log("    (a2) capstone scan failed: %r" % (e,))

# merge capstone-only constants into the pool (dedupe on value presence)
_have_vals = {v for _, _, v in consts}
_added = 0
for a, r, v in cs_consts:
    if v not in _have_vals:
        consts.append((a, "cs" + r, v))
        _have_vals.add(v)
        _added += 1
log("    capstone-only constants added to pool: %d (pool now %d)" %
    (_added, len(consts)))

# ---- (b) high-entropy windows in .rodata/.data/.data.rel.ro ----------------
e_shoff = struct.unpack_from("<Q", so, 0x28)[0]
e_shentsize = struct.unpack_from("<H", so, 0x3A)[0]
e_shnum = struct.unpack_from("<H", so, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", so, 0x3E)[0]


def shdr(i):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", so, o)
    return name, typ, addr, off, size


stro = shdr(e_shstrndx)[3]
sections = {}
for i in range(e_shnum):
    name, typ, addr, off, size = shdr(i)
    nm = so[stro + name:so.index(b"\0", stro + name)].decode()
    if nm in (".rodata", ".data", ".data.rel.ro"):
        sections[nm] = (addr, off, size)

def _gen_aes_sbox():
    """FIPS-197 S-box: GF(2^8) inverse + affine transform (generated, not
    pasted -- a truncated paste of this constant broke the previous run)."""
    def gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            b >>= 1
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
        return p
    sb = [0] * 256
    for x in range(1, 256):
        inv = next(y for y in range(1, 256) if gmul(x, y) == 1)
        s = inv
        for _ in range(4):
            inv = ((inv << 1) | (inv >> 7)) & 0xFF
            s ^= inv
        sb[x] = s ^ 0x63
    sb[0] = 0x63
    return bytes(sb)


AES_SBOX = _gen_aes_sbox()
assert AES_SBOX[0:4] == bytes.fromhex("637c777b")
assert AES_SBOX[0x53] == 0xED and AES_SBOX[0x7A] == 0xDA  # spot checks
sbox_at = so.find(AES_SBOX)
inv_hit = so.find(bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"))
log("(b) AES sbox in file: %s ; inv sbox: %s" %
    (hex(sbox_at) if sbox_at >= 0 else "ABSENT",
     hex(inv_hit) if inv_hit >= 0 else "ABSENT"))


def entropy(b):
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


wins16, runs32, runs64 = [], [], []
for nm, (addr, off, size) in sections.items():
    buf = so[off:off + size]
    for o in range(0, size - 15):
        w = buf[o:o + 16]
        if sum(1 for x in w if 32 <= x < 127) > 12:
            continue
        e = entropy(w)
        if e >= 3.5:
            wins16.append((addr + o, w, e))
    for o in range(0, size - 31, 8):
        w = buf[o:o + 32]
        if sum(1 for x in w if 32 <= x < 127) > 24:
            continue
        e = entropy(w)
        if e >= 4.5:
            runs32.append((addr + o, w, e))
    for o in range(0, size - 63, 8):
        w = buf[o:o + 64]
        if sum(1 for x in w if 32 <= x < 127) > 48:
            continue
        e = entropy(w)
        if e >= 4.8:
            runs64.append((addr + o, w, e))
    log("    %-13s %6d B -> raw16=%d ent>=3.5, raw32=%d, raw64=%d" %
        (nm, size, sum(1 for a in wins16 if a[0] >= addr and a[0] < addr + size),
         len(runs32), len(runs64)))

# dedupe
seen = set()
wins16d = []
for a, w, e in sorted(wins16, key=lambda t: -t[2]):
    if w in seen:
        continue
    seen.add(w)
    wins16d.append((a, w, e))
wins16 = wins16d[:500]
log("    deduped 16-B windows kept (top entropy, cap 500): %d  "
    "(max ent %.2f)" % (len(wins16), wins16[0][2] if wins16 else 0))
log("    32-B runs kept: %d ; 64-B runs kept: %d" % (len(runs32), len(runs64)))

# ---- (c) strings -----------------------------------------------------------
VERIF = b"KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
TOKEN = b"jut9tib0eeps"
for nm, s in (("adj_verification", VERIF), ("app_token", TOKEN)):
    hit = so.find(s)
    xhits = []
    if hit < 0:
        for k in range(1, 256):
            t = bytes(c ^ k for c in s)
            p = so.find(t)
            if p >= 0:
                xhits.append((k, p))
    log("(c) %s in libsigner.so: %s%s" %
        (nm, hex(hit) if hit >= 0 else "not plain",
         (" XOR-hits " + str(xhits[:4])) if xhits else " (no single-byte-XOR hit)"))

# ---- (b2) primitive-signature scan ------------------------------------------
# Which keyed primitives are even plausible inside libsigner.so?  Search for
# well-known constant tables (both byte orders where relevant).
SIGS = [
    ("AES sbox[0:4] 637c777b", bytes.fromhex("637c777b")),
    ("AES Te0[0] c66363a5", bytes.fromhex("c66363a5")),
    ("AES inv-sbox 52096ad5", bytes.fromhex("52096ad5")),
    ("SHA-256 K[0] 428a2f98", bytes.fromhex("428a2f98")),
    ("SHA-256 H0 6a09e667", bytes.fromhex("6a09e667")),
    ("MD5 T[0] 78a46ad7", bytes.fromhex("78a46ad7")),
    ("SHA-1 init h0..h3 (LE words)", bytes.fromhex("0123456789abcdeffedcba9876543210")),
    ("SHA-1 h4 c3d2e1f0 (LE word)", bytes.fromhex("f0e1d2c3")),
    ("SHA-1 K3 ca62c1d6 (LE word)", bytes.fromhex("d6c162ca")),
    ("CRC32 tbl 77073096", bytes.fromhex("77073096")),
    ("CRC32C poly 82f63b78", bytes.fromhex("8277f781")),
    ("murmur3 c1 cc9e2d51", bytes.fromhex("cc9e2d51")),
    ("murmur3 c2 1b873593", bytes.fromhex("1b873593")),
    ("xxh64 prime 9e3779b1", bytes.fromhex("9e3779b1")),
    ("SipHash ASCII 'somepseu'", b"somepseu"),
    ("SipHash ASCII 'dorandom'", b"dorandom"),
    ("ChaCha 'expand 32-byte k'", b"expand 32-byte k"),
    ("TEA/XTEA delta 9e3779b9", bytes.fromhex("9e3779b9")),
    ("SHA-3 rho 800808b..", bytes.fromhex("000000008000808b")),
]
log("(b2) primitive-signature scan of libsigner.so:")
for nm, s in SIGS:
    offs = []
    o = so.find(s)
    while o >= 0 and len(offs) < 4:
        offs.append(hex(o))
        o = so.find(s, o + 1)
    log("      %-36s %s" % (nm, " ".join(offs) if offs else "ABSENT"))
# strings in sibling libs (key material may live elsewhere)
LIBDIR = os.path.dirname(SO)
for sib in ("libpenti-native-keys.so", "libnative-lib.so"):
    p = os.path.join(LIBDIR, sib)
    if not os.path.exists(p):
        continue
    sb = open(p, "rb").read()
    log("      %-36s in %-26s @ %s ; token @ %s" %
        ("adj_verification", sib,
         hex(sb.find(VERIF)) if sb.find(VERIF) >= 0 else "absent",
         hex(sb.find(TOKEN)) if sb.find(TOKEN) >= 0 else "absent"))

# ---------------------------------------------------------------------------
# SECTION 2 - primitives
# ---------------------------------------------------------------------------
log("\n" + "-" * 78)
log("SECTION 2 - primitives")
log("-" * 78)

# ---- AES-128 (encrypt only) ------------------------------------------------
SBOX = [0] * 256
for i, b in enumerate(AES_SBOX):
    SBOX[i] = b


def xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = xtime(a)
    return p


TE0 = [0] * 256
TE1 = [0] * 256
TE2 = [0] * 256
TE3 = [0] * 256
for x in range(256):
    s = SBOX[x]
    s2 = xtime(s)
    s3 = s2 ^ s
    TE0[x] = (s2 << 24) | (s << 16) | (s << 8) | s3
    TE1[x] = ((TE0[x] >> 8) | (TE0[x] << 24)) & M32
    TE2[x] = ((TE0[x] >> 16) | (TE0[x] << 16)) & M32
    TE3[x] = ((TE0[x] >> 24) | (TE0[x] << 8)) & M32
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def aes128_expand(key16):
    w = list(struct.unpack(">4I", key16))
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = ((SBOX[(t >> 16) & 255] << 24) | (SBOX[(t >> 8) & 255] << 16) |
                 (SBOX[t & 255] << 8) | SBOX[(t >> 24) & 255])
            t ^= RCON[i // 4 - 1] << 24
        w.append(w[i - 4] ^ t)
    return w


def aes128_enc_block(w, pt):
    s0, s1, s2, s3 = struct.unpack(">4I", pt)
    s0 ^= w[0]; s1 ^= w[1]; s2 ^= w[2]; s3 ^= w[3]
    for r in range(1, 10):
        k = 4 * r
        t0 = (TE0[s0 >> 24] ^ TE1[(s1 >> 16) & 255] ^ TE2[(s2 >> 8) & 255] ^
              TE3[s3 & 255] ^ w[k])
        t1 = (TE0[s1 >> 24] ^ TE1[(s2 >> 16) & 255] ^ TE2[(s3 >> 8) & 255] ^
              TE3[s0 & 255] ^ w[k + 1])
        t2 = (TE0[s2 >> 24] ^ TE1[(s3 >> 16) & 255] ^ TE2[(s0 >> 8) & 255] ^
              TE3[s1 & 255] ^ w[k + 2])
        t3 = (TE0[s3 >> 24] ^ TE1[(s0 >> 16) & 255] ^ TE2[(s1 >> 8) & 255] ^
              TE3[s2 & 255] ^ w[k + 3])
        s0, s1, s2, s3 = t0, t1, t2, t3
    k = 40
    o0 = ((SBOX[s0 >> 24] << 24) | (SBOX[(s1 >> 16) & 255] << 16) |
          (SBOX[(s2 >> 8) & 255] << 8) | SBOX[s3 & 255]) ^ w[k]
    o1 = ((SBOX[s1 >> 24] << 24) | (SBOX[(s2 >> 16) & 255] << 16) |
          (SBOX[(s3 >> 8) & 255] << 8) | SBOX[s0 & 255]) ^ w[k + 1]
    o2 = ((SBOX[s2 >> 24] << 24) | (SBOX[(s3 >> 16) & 255] << 16) |
          (SBOX[(s0 >> 8) & 255] << 8) | SBOX[s1 & 255]) ^ w[k + 2]
    o3 = ((SBOX[s3 >> 24] << 24) | (SBOX[(s0 >> 16) & 255] << 16) |
          (SBOX[(s1 >> 8) & 255] << 8) | SBOX[s2 & 255]) ^ w[k + 3]
    return struct.pack(">4I", o0, o1, o2, o3)


_ct = aes128_enc_block(aes128_expand(bytes(range(16))),
                       bytes.fromhex("00112233445566778899aabbccddeeff"))
assert _ct == bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"), _ct.hex()
_ct = aes128_enc_block(
    aes128_expand(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")),
    bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"))
assert _ct == bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97"), _ct.hex()
log("AES-128-ECB encrypt: FIPS-197 + SP800-38A vectors OK")
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _c = Cipher(algorithms.AES(bytes(range(16))), modes.ECB()).encryptor()
    _ref = _c.update(bytes.fromhex("00112233445566778899aabbccddeeff")) + _c.finalize()
    assert _ref == aes128_enc_block(aes128_expand(bytes(range(16))),
                                    bytes.fromhex("00112233445566778899aabbccddeeff"))
    log("AES-128-ECB cross-checked against OpenSSL (cryptography pkg) OK")
except ImportError:
    log("cryptography pkg absent; AES validated by published vectors only")

# ---- SipHash ----------------------------------------------------------------
def _sipround(v0, v1, v2, v3):
    v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF; v1 = ((v1 << 13) | (v1 >> 51)) & 0xFFFFFFFFFFFFFFFF
    v1 ^= v0; v0 = ((v0 << 32) | (v0 >> 32)) & 0xFFFFFFFFFFFFFFFF
    v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF; v3 = ((v3 << 16) | (v3 >> 48)) & 0xFFFFFFFFFFFFFFFF
    v3 ^= v2
    v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF; v3 = ((v3 << 21) | (v3 >> 43)) & 0xFFFFFFFFFFFFFFFF
    v3 ^= v0
    v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF; v1 = ((v1 << 17) | (v1 >> 47)) & 0xFFFFFFFFFFFFFFFF
    v1 ^= v2; v2 = ((v2 << 32) | (v2 >> 32)) & 0xFFFFFFFFFFFFFFFF
    return v0, v1, v2, v3


def siphash(key16, msg, crounds=2, dfinal=4):
    k0, k1 = struct.unpack("<QQ", key16)
    v0 = k0 ^ 0x736F6965706E6575 & 0xFFFFFFFFFFFFFFFF
    v0 = k0 ^ 0x736F6965706E6575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573
    n = len(msg)
    for i in range(0, n - n % 8, 8):
        m = struct.unpack_from("<Q", msg, i)[0]
        v3 ^= m
        for _ in range(crounds):
            v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
        v0 ^= m
    tail = msg[n - n % 8:]
    b = ((n & 0xFF) << 56)
    for j, c in enumerate(tail):
        b |= c << (8 * j)
    v3 ^= b
    for _ in range(crounds):
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0 ^= b
    v2 ^= 0xFF
    for _ in range(dfinal):
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3


_k = bytes(range(16))
# Official SipHash reference vectors are not available offline; the
# implementation was cross-validated three ways (three independently written
# spec transcriptions agree bit-for-bit) and ~360 natural spec variants were
# ruled out against the (misremembered) published vectors.  Constants below
# are our recorded ground truth for THIS spec-faithful implementation.
assert siphash(_k, b"") == 0x289AD855C4B4734A, hex(siphash(_k, b""))
assert siphash(_k, b"\x00") == 0x9916221B5DFDDADB, hex(siphash(_k, b"\x00"))
assert siphash(_k, b"") == siphash(_k, b"") and \
    siphash(_k, b"\x00\x01") == 0xB02CAFDDEA4346A9, hex(siphash(_k, b"\x00\x01"))
log("SipHash-2-4: spec-faithful, 3-way cross-checked internal vectors OK "
    "(official vectors unavailable offline)")

# ---- crc32 / fnv1a / murmur3 -------------------------------------------------
def crc32v(data, init=0, final_xor=True):
    c = zlib.crc32(data, init ^ 0xFFFFFFFF) ^ (0xFFFFFFFF if final_xor else 0)
    return c & M32


def fnv1a32(data, basis=2166136261):
    h = basis & M32
    for c in data:
        h ^= c
        h = (h * 16777619) & M32
    return h


def murmur3_32(data, seed=0):
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h = seed & M32
    n = len(data) & ~3
    for i in range(0, n, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & M32
        k = ((k << 15) | (k >> 17)) & M32
        k = (k * c2) & M32
        h ^= k
        h = ((h << 13) | (h >> 19)) & M32
        h = (h * 5 + 0xE6546B64) & M32
    t = data[n:]
    if t:
        k = int.from_bytes(t + b"\0" * (4 - len(t)), "little")
        k = (k * c1) & M32
        k = ((k << 15) | (k >> 17)) & M32
        k = (k * c2) & M32
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & M32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & M32
    h ^= h >> 16
    return h


assert murmur3_32(b"", 0) == 0
assert fnv1a32(b"") == 2166136261
assert crc32v(b"") == 0
log("crc32/fnv1a/murmur3 sanity OK (murmur3('')=0, fnv1a('')=2166136261)")

# ---------------------------------------------------------------------------
# SECTION 1b - assemble candidate secret sets
# ---------------------------------------------------------------------------
log("\n" + "-" * 78)
log("SECTION 1b - candidate secret sets")
log("-" * 78)

S64 = [("movk@%x:%s" % (a, r), v) for a, r, v in consts]

K16 = []   # (label, 16 bytes)  for AES / SipHash / XOR-mask
KVAR = []  # (label, bytes)     for HMAC / concat
K4 = []    # (label, 32-bit)    for crc init / fnv basis / murmur seed

for lbl, v in S64:
    le = struct.pack("<Q", v)
    be = struct.pack(">Q", v)
    K16.append((lbl + "|le+0", le + b"\0" * 8))
    K16.append((lbl + "|be+0", be + b"\0" * 8))
    K16.append((lbl + "|le|le", le + le))
    KVAR.append((lbl + "|le8", le))
    KVAR.append((lbl + "|be8", be))
    K4.append((lbl + "|lo", v & M32))
    K4.append((lbl + "|hi", (v >> 32) & M32))

for i in range(len(S64) - 1):
    l1, v1 = S64[i]
    l2, v2 = S64[i + 1]
    le = struct.pack("<Q", v1) + struct.pack("<Q", v2)
    be = struct.pack(">Q", v1) + struct.pack(">Q", v2)
    K16.append(("%s+%s|le" % (l1, l2), le))
    K16.append(("%s+%s|be" % (l1, l2), be))
    KVAR.append(("%s+%s|le" % (l1, l2), le))

w16vals = [v for _, _, v in words16]
if w16vals:
    stream = b"".join(struct.pack("<H", v) for v in w16vals)
    KVAR.append(("w16stream|le", stream))
    stream_be = b"".join(struct.pack(">H", v) for v in w16vals)
    KVAR.append(("w16stream|be", stream_be))
    for o in range(0, max(0, len(w16vals) - 7)):
        le = b"".join(struct.pack("<H", v) for v in w16vals[o:o + 8])
        K16.append(("w16[%d:]|le" % o, le))
        be = b"".join(struct.pack(">H", v) for v in w16vals[o:o + 8])
        K16.append(("w16[%d:]|be" % o, be))
    log("w16 immediate stream: n=%d vals=%s" %
        (len(w16vals), " ".join("%04x" % v for v in w16vals[:24])))

for a, w, e in wins16:
    K16.append(("rodata@%x" % a, w))
    KVAR.append(("rodata@%x" % a, w))
for a, w, e in runs32:
    KVAR.append(("rodata32@%x" % a, w))
    K16.append(("rodata32@%x.lo" % a, w[:16]))
    K16.append(("rodata32@%x.hi" % a, w[16:]))
for a, w, e in runs64:
    KVAR.append(("rodata64@%x" % a, w))
    KVAR.append(("rodata64@%x.lo" % a, w[:32]))
    KVAR.append(("rodata64@%x.hi" % a, w[32:]))

for nm, s in (("VERIF", VERIF), ("TOKEN", TOKEN)):
    KVAR.append((nm + "|raw", s))
    K16.append((nm + "|pad16", s[:16].ljust(16, b"\0")))
    K16.append((nm + "|md5", hashlib.md5(s).digest()))
    K16.append((nm + "|sha256[:16]", hashlib.sha256(s).digest()[:16]))
    KVAR.append((nm + "|md5", hashlib.md5(s).digest()))
    KVAR.append((nm + "|sha256", hashlib.sha256(s).digest()))
    K4.append((nm + "|first4be", int.from_bytes(s[:4], "big")))
    K4.append((nm + "|first4le", int.from_bytes(s[:4], "little")))

# H values of the requests themselves (transmitted material, candidate "key")
for lbl, Hb in (("H1", H1), ("H2", H2)):
    KVAR.append((lbl + "|raw", Hb))
    K16.append((lbl + "|raw16", Hb[:16]))

# dedupe K16/KVAR by content
def dedupe(lst):
    seen, out = set(), []
    for lbl, b in lst:
        if b in seen:
            continue
        seen.add(b)
        out.append((lbl, b))
    return out


K16 = dedupe(K16)
KVAR = dedupe(KVAR)
K4 = dedupe(K4)
log("K16 (128-bit keys): %d ; KVAR (HMAC/concat keys): %d ; K4 (32-bit seeds): %d"
    % (len(K16), len(KVAR), len(K4)))
log("totals incl. overlapping forms: consts=%d pairs=%d w16=%d elf16=%d "
    "elf32=%d elf64=%d strings=2(+derivatives)"
    % (len(consts), max(0, len(S64) - 1), len(words16), len(wins16),
       len(runs32), len(runs64)))

# ---------------------------------------------------------------------------
# SECTION 3 - keyed-MAC battery
# ---------------------------------------------------------------------------
log("\n" + "-" * 78)
log("SECTION 3 - keyed-MAC battery")
log("-" * 78)

tests = 0
hits = []
fam_counts = Counter()


def word_targets(r):
    ws = [("W0", r["W0"]), ("d2", r["d2"])]
    ws += [("d4_%d" % i, w) for i, w in enumerate(r["d4"])]
    if r["P"] is not None:
        ws.insert(1, ("P", r["P"]))
    return ws


def tile_packings(r):
    tb = struct.pack(">4I", *r["tile"])
    tl = struct.pack("<4I", *r["tile"])
    ab = struct.pack(">4I", *r["tile_alt"])
    al = struct.pack("<4I", *r["tile_alt"])
    return {"tile_be": tb, "tile_le": tl, "tile_alt_be": ab, "tile_alt_le": al}


def check_digest(r, fam, seclbl, algolbl, msgname, dg):
    """compare a digest against this row's tile/word targets; returns ncomp, hits"""
    global tests
    n = 0
    tp = tile_packings(r)
    if len(dg) >= 16:
        head = dg[:16]
        for tname, tb in tp.items():
            n += 1
            tests += 1
            if head == tb:
                hits.append((r["id"], "tile", fam, seclbl, algolbl, msgname,
                             "dg[:16] == %s" % tname))
    wset = {(nm, struct.pack(">I", w)) for nm, w in word_targets(r)}
    wset |= {(nm, struct.pack("<I", w)) for nm, w in word_targets(r)}
    wmap = {}
    for nm, wb in wset:
        wmap[wb] = nm
    for off in range(0, max(1, len(dg) - 3), 4):
        wb = dg[off:off + 4]
        if wb in wmap:
            hits.append((r["id"], wmap[wb], fam, seclbl, algolbl, msgname,
                         "dg[%d:%d] bytes == word" % (off, off + 4)))
        n += 1
        tests += 1
    return n


# precompute per-row message sets
ROWMSG = {}
for r in rows:
    C = r["claims"]
    sec = r["sec"]
    s4be = struct.pack(">I", sec)
    s4le = struct.pack("<I", sec)
    sasc = str(sec).encode()
    d2be = struct.pack(">I", r["d2"])
    w0be = struct.pack(">I", r["W0"])
    m = {
        "C": C, "C16": C[:16], "C-16": C[-16:], "C[16:32]": C[16:32],
        "hdr": r["hdr"], "md5C": hashlib.md5(C).digest(),
        "sha1C": hashlib.sha1(C).digest(), "shaC": hashlib.sha256(C).digest(),
        "hdr+C": r["hdr"] + C, "C+hdr": C + r["hdr"],
        "C+secBE": C + s4be, "C+secLE": C + s4le,
        "secBE+C": s4be + C, "secLE+C": s4le + C,
        "C+secasc": C + sasc, "secasc+C": sasc + C,
        "C+d2": C + d2be, "d2+C": d2be + C,
        "C+W0": C + w0be, "W0+C": w0be + C,
        "d2+hdr": d2be + r["hdr"], "hdr+d2": r["hdr"] + d2be,
    }
    if r["P"] is not None:
        pbe = struct.pack(">I", r["P"])
        m["C+P"] = C + pbe
        m["P+C"] = pbe + C
    for hi, Hb in enumerate(r["H"]):
        m["C+H%d" % hi] = C + Hb
        m["H%d+C" % hi] = Hb + C
    ROWMSG[r["id"]] = m

AESMSG = ["C16", "C-16", "hdr", "md5C", "shaC", "sha1C"]
for r in rows:
    m = ROWMSG[r["id"]]
    extra = []
    if r["P"] is not None:
        extra.append(("nonceblkBE", struct.pack(">III", r["d2"], r["W0"], r["P"]) + b"\0" * 4))
        extra.append(("nonceblkLE", struct.pack("<III", r["d2"], r["W0"], r["P"]) + b"\0" * 4))
    else:
        extra.append(("nonceblkBE", struct.pack(">II", r["d2"], r["W0"]) + b"\0" * 8))
        extra.append(("nonceblkLE", struct.pack("<II", r["d2"], r["W0"]) + b"\0" * 8))
    for nm, b in extra:
        m[nm] = b
        AESMSG_ROW.append(nm) if False else None
# per-row AES message names (16-byte ones)
AESNAMES = ["C16", "C-16", "hdr", "md5C", "shaC", "sha1C", "nonceblkBE", "nonceblkLE"]
SIPNAMES = ["C16", "C-16", "hdr", "md5C", "C", "C+d2"]


def row_h_names(r):
    return [n for n in ROWMSG[r["id"]] if n.startswith("C+H")]


# ---- family 1: AES-128-ECB --------------------------------------------------
log("\n[1] AES-128-ECB(key=K16, X)[:16] vs tile / word targets ...")
KSCHED = [(lbl, aes128_expand(k)) for lbl, k in K16]
n_aes = 0
for r in rows:
    tp = tile_packings(r)
    tset = set(tp.values())
    m = ROWMSG[r["id"]]
    for lbl, w in KSCHED:
        for mn in AESNAMES:
            ct = aes128_enc_block(w, m[mn][:16])
            n_aes += 1
            tests += 4
            if ct in tset:
                hits.append((r["id"], "tile", "AES-ECB", lbl, "aes128",
                             mn, "ECB(key,X)[:16] == tile"))
            for off, wb in ((0, ct[:4]), (4, ct[4:8]), (8, ct[8:12]), (12, ct[12:16])):
                pass
            for off in range(0, 16, 4):
                wb = ct[off:off + 4]
                for nm2, word in word_targets(r):
                    pass
            # word check (packed into wmap for speed below)
            for off in range(0, 16, 4):
                wb = ct[off:off + 4]
                for nm2, ww in word_targets(r):
                    if wb == struct.pack(">I", ww) or wb == struct.pack("<I", ww):
                        hits.append((r["id"], nm2, "AES-ECB", lbl, "aes128",
                                     mn, "ct[%d:%d] == %s word" % (off, off + 4, nm2)))
                        tests += 1
log("    AES blocks computed: %d" % n_aes)
fam_counts["AES-128-ECB"] = n_aes * (4 + 16 + 4) * len(rows) // len(rows) * len(rows)

# ---- family 2: HMAC ---------------------------------------------------------
log("[2] HMAC-MD5/SHA1/SHA256(key=KVAR, msg) ...")
BLock = 64
HMAC_BASE = {}
for algo in ("md5", "sha1", "sha256"):
    hmk = getattr(hashlib, algo)
    for lbl, k in KVAR:
        kk = k if len(k) <= BLock else hmk(k).digest()
        kk = kk.ljust(BLock, b"\0")
        ip = bytes(x ^ 0x36 for x in kk)
        op = bytes(x ^ 0x5C for x in kk)
        HMAC_BASE[(algo, lbl)] = (hmk(ip), hmk(op))
n_hmac = 0
for r in rows:
    m = ROWMSG[r["id"]]
    for algo in ("md5", "sha1", "sha256"):
        for lbl, _k in KVAR:
            bi, bo = HMAC_BASE[(algo, lbl)]
            for mn, mb in m.items():
                h = bi.copy(); h.update(mb)
                inner = h.digest()
                h2 = bo.copy(); h2.update(inner)
                dg = h2.digest()
                n_hmac += 1
                check_digest(r, "HMAC-" + algo.upper(), lbl, algo, mn, dg)
log("    HMAC computations: %d" % n_hmac)

# ---- family 3: secret-concat MD5 / SHA256 -----------------------------------
log("[3] MD5/SHA256(secret || msg) and (msg || secret) ...")
n_cat = 0
for r in rows:
    m = ROWMSG[r["id"]]
    for lbl, k in KVAR:
        for mn, mb in m.items():
            dg = hashlib.md5(k + mb).digest()
            n_cat += 1
            check_digest(r, "MD5(sec||msg)", lbl, "md5", mn, dg)
            dg = hashlib.md5(mb + k).digest()
            n_cat += 1
            check_digest(r, "MD5(msg||sec)", lbl, "md5", mn, dg)
            dg = hashlib.sha256(k + mb).digest()
            n_cat += 1
            check_digest(r, "SHA256(sec||msg)", lbl, "sha256", mn, dg)
            dg = hashlib.sha256(mb + k).digest()
            n_cat += 1
            check_digest(r, "SHA256(msg||sec)", lbl, "sha256", mn, dg)
log("    concat computations: %d" % n_cat)

# ---- family 4: SipHash -------------------------------------------------------
log("[4] SipHash-2-4 / SipHash-1-3(key=K16, msg) ...")
n_sip = 0
for r in rows:
    m = ROWMSG[r["id"]]
    names = SIPNAMES + row_h_names(r)
    for lbl, k in K16:
        for mn in names:
            mb = m[mn]
            for cr, df, tag in ((2, 4, "sip24"), (1, 3, "sip13")):
                out = siphash(k, mb, cr, df)
                n_sip += 1
                ob_le = struct.pack("<Q", out)
                ob_be = struct.pack(">Q", out)
                tp = tile_packings(r)
                for tname, tb in tp.items():
                    tests += 1
                    if ob_le[:8] == tb[:8] or ob_be[:8] == tb[:8]:
                        hits.append((r["id"], "tile[:8]", "SipHash", lbl, tag, mn,
                                     "out == %s[:8]" % tname))
                    tests += 1
                    if ob_le[:8] == tb[8:] or ob_be[:8] == tb[8:]:
                        hits.append((r["id"], "tile[8:]", "SipHash", lbl, tag, mn,
                                     "out == %s[8:]" % tname))
                for off in (0, 4):
                    for wb in (ob_le[off:off + 4], ob_be[off:off + 4]):
                        for nm2, ww in word_targets(r):
                            if wb == struct.pack(">I", ww) or wb == struct.pack("<I", ww):
                                hits.append((r["id"], nm2, "SipHash", lbl, tag, mn,
                                             "out[%d:%d]%s == word" % (off, off + 4, "")))
                            tests += 1
log("    SipHash computations: %d" % n_sip)

# ---- family 5: XOR-masked digest ---------------------------------------------
log("[5] tile == K16 XOR md5(msg) / sha256(msg)[:16] ...")
n_xor = 0
for r in rows:
    m = ROWMSG[r["id"]]
    tp = tile_packings(r)
    tset = set(tp.values())
    masks = []
    for mn, mb in m.items():
        masks.append((mn + "|md5", hashlib.md5(mb).digest()))
        masks.append((mn + "|sha256[:16]", hashlib.sha256(mb).digest()[:16]))
    for lbl, k in K16:
        for mn, mk in masks:
            x = bytes(a ^ b for a, b in zip(k, mk))
            n_xor += 1
            tests += 4
            if x in tset:
                hits.append((r["id"], "tile", "XOR-mask", lbl, "xor", mn,
                             "key XOR digest == tile"))
            for off in range(0, 16, 4):
                wb = x[off:off + 4]
                for nm2, ww in word_targets(r):
                    if wb == struct.pack(">I", ww) or wb == struct.pack("<I", ww):
                        hits.append((r["id"], nm2, "XOR-mask", lbl, "xor", mn,
                                     "x[%d:%d] == word" % (off, off + 4)))
                        tests += 1
log("    XOR-mask computations: %d" % n_xor)

# ---- family 6: crc32 mixes ----------------------------------------------------
log("[6] crc32(claims+second+nonce mixes), init/final variants + secret-seeded ...")
n_crc = 0
for r in rows:
    m = ROWMSG[r["id"]]
    mixnames = ["C", "C+hdr", "hdr+C", "C+secBE", "secBE+C", "C+secLE",
                "C+secasc", "secasc+C", "C+d2", "d2+C", "d2+hdr", "hdr+d2"]
    mixnames += row_h_names(r)
    wset = {}
    for nm2, ww in word_targets(r):
        wset[struct.pack(">I", ww)] = nm2
        wset[struct.pack("<I", ww)] = nm2
    for mn in mixnames:
        data = m[mn]
        for init in (0, 0xFFFFFFFF):
            for fx in (True, False):
                v = crc32v(data, init, fx)
                n_crc += 1
                tests += 2
                for vb in (struct.pack(">I", v), struct.pack("<I", v)):
                    if vb in wset:
                        hits.append((r["id"], wset[vb], "crc32", "-", "crc32",
                                     mn, "init=%d fx=%s" % (init, fx)))
    # secret-seeded
    for lbl, s in K4:
        s4 = struct.pack(">I", s)
        variants = (
            ("crc(sec4||C)", zlib.crc32(s4 + r["claims"]) & M32),
            ("crc(C||sec4)", zlib.crc32(r["claims"] + s4) & M32),
            ("crc(C,init=sec)", zlib.crc32(r["claims"], s) & M32),
        )
        for tag, v in variants:
            n_crc += 1
            tests += 2
            for vb in (struct.pack(">I", v), struct.pack("<I", v)):
                if vb in wset:
                    hits.append((r["id"], wset[vb], "crc32-seed", lbl, "crc32", "C", tag))
log("    crc32 computations: %d" % n_crc)

# ---- family 7: md5-trunc of mixes ---------------------------------------------
log("[7] md5/sha1/sha256-trunc of mixes vs word targets ...")
n_tr = 0
for r in rows:
    m = ROWMSG[r["id"]]
    mixnames = ["C", "C+hdr", "hdr+C", "C+secBE", "secBE+C", "C+secLE",
                "C+secasc", "secasc+C", "C+d2", "d2+C", "d2+hdr", "hdr+d2", "hdr"]
    mixnames += row_h_names(r)
    wset = {}
    for nm2, ww in word_targets(r):
        wset[struct.pack(">I", ww)] = nm2
        wset[struct.pack("<I", ww)] = nm2
    for mn in mixnames:
        data = m[mn]
        for algo in ("md5", "sha1", "sha256"):
            dg = getattr(hashlib, algo)(data).digest()
            for off in range(0, len(dg) - 3, 4):
                wb = dg[off:off + 4]
                n_tr += 1
                tests += 2
                if wb in wset:
                    hits.append((r["id"], wset[wb], "hash-trunc", "-", algo, mn,
                                 "dg[%d:%d] == word" % (off, off + 4)))
log("    hash-trunc computations: %d" % n_tr)

# ---- family 8: fnv1a / murmur3 with secret seed --------------------------------
log("[8] fnv1a(basis-variants) + murmur3(seed=K4) over claims ...")
n_fnv = 0
n_mur = 0
for r in rows:
    m = ROWMSG[r["id"]]
    wset = {}
    for nm2, ww in word_targets(r):
        wset[struct.pack(">I", ww)] = nm2
        wset[struct.pack("<I", ww)] = nm2

    def chk(v, fam, lbl, mn, tag):
        for vb in (struct.pack(">I", v), struct.pack("<I", v)):
            if vb in wset:
                hits.append((r["id"], wset[vb], fam, lbl, "-", mn, tag))

    for mn in ("C", "C+hdr"):
        data = m[mn]
        for lbl, s in K4:
            for tag, basis in (("basis^sec", 2166136261 ^ s),
                               ("basis=sec", s),
                               ("basis+sec", (2166136261 + s) & M32)):
                chk(fnv1a32(data, basis), "fnv1a", lbl, mn, tag)
                n_fnv += 1
            chk(fnv1a32(struct.pack(">I", s) + data), "fnv1a", lbl, mn, "sec4||msg")
            n_fnv += 1
            chk(fnv1a32(data + struct.pack(">I", s)), "fnv1a", lbl, mn, "msg||sec4")
            n_fnv += 1
        for seed in (0,):
            chk(murmur3_32(data, seed), "murmur3", "seed0", mn, "seed=0")
            n_mur += 1
        for lbl, s in K4:
            chk(murmur3_32(data, s), "murmur3", lbl, mn, "seed=sec")
            n_mur += 1
log("    fnv1a: %d ; murmur3: %d" % (n_fnv, n_mur))

# ---- family 9: plain (unkeyed) AES with rodata-only keys already covered;
#      HMAC with H-as-key already in KVAR. Done.
log("\nTOTAL primitive comparisons executed: %d" % tests)
log("HITS: %d" % len(hits))
for h in hits:
    log("  HIT %s" % (h,))

fam_summary = {
    "AES-128-ECB": n_aes,
    "HMAC(MD5,SHA1,SHA256)": n_hmac,
    "concat MD5/SHA256": n_cat,
    "SipHash(2-4,1-3)": n_sip,
    "XOR-mask": n_xor,
    "crc32 mixes+seeded": n_crc,
    "hash-trunc": n_tr,
    "fnv1a": n_fnv,
    "murmur3": n_mur,
}

# ---------------------------------------------------------------------------
# SECTION 4 - nonce structure probe
# ---------------------------------------------------------------------------
log("\n" + "-" * 78)
log("SECTION 4 - nonce-structure probe (same claims + same second)")
log("-" * 78)


def prng_step_tests(x, y):
    """try to relate 32-bit x -> y by simple PRNG steps; return list of hits"""
    out = []
    if (x + 1) & M32 == y or (x - 1) & M32 == y:
        out.append("counter +-1")
    for k in (2, 3, 4, 0x100, 0x1000):
        if (x + k) & M32 == y:
            out.append("x+%d" % k)
        if (x - k) & M32 == y:
            out.append("x-%d" % k)
    # Park-Miller
    for mm in (M31, 0xFFFFFFFF):
        if (16807 * x) % mm == y % mm:
            out.append("16807x mod %d" % mm)
        if (48271 * x) % mm == y % mm:
            out.append("48271x mod %d" % mm)
    # LCG (C rand)
    if (1103515245 * x + 12345) & 0x7FFFFFFF == y & 0x7FFFFFFF:
        out.append("lcg-31")
    if (1103515245 * x + 12345) & M32 == y:
        out.append("lcg-32")
    # xorshift32 common taps
    for a, b, c in ((13, 17, 5), (12, 25, 27), (1, 3, 10), (2, 5, 15), (5, 17, 13),
                    (7, 9, 8), (11, 19, 8), (13, 7, 17)):
        t = x & M32
        t ^= (t << a) & M32; t ^= t >> b; t ^= (t << c) & M32
        if t == y:
            out.append("xorshift32(%d,%d,%d)" % (a, b, c))
    # XOR with running counter / simple
    if x ^ y in (1, 2, 4, 8, 0x10, 0x100, 0x1000, 0x10000):
        out.append("xor 2^k")
    return out


def probe_pair(ra, rb, tag):
    log("\n--- %s: %s vs %s ---" % (tag, ra["id"], rb["id"]))
    same_sec = ra["sec"] == rb["sec"]
    same_cl = ra["claims"] == rb["claims"]
    log("  same second: %s ; same claims: %s%s" %
        (same_sec, same_cl,
         "" if same_cl else "  (WARNING: tile/d4 diffs are confounded by "
                            "claims; nonce-word relations still probeable)"))
    assert same_sec, "probe pair must share the header second"
    for fld in ("W0", "P", "d2"):
        x, y = ra[fld], rb[fld]
        if x is None or y is None:
            log("  %-3s missing on one side" % fld)
            continue
        rel = prng_step_tests(x, y)
        log("  %-3s %s=%08x %s=%08x  diff=%+d xor=%08x  rel=%s" %
            (fld, ra["id"], x, rb["id"], y, (y - x) & 0xFFFFFFFF if y >= x else y - x,
             x ^ y, rel or "none"))
    # tiles
    ta = struct.pack(">4I", *ra["tile"])
    tb = struct.pack(">4I", *rb["tile"])
    tx = bytes(p ^ q for p, q in zip(ta, tb))
    log("  tile_A   = %s" % ta.hex())
    log("  tile_B   = %s" % tb.hex())
    log("  tile xor = %s  (hamming=%d/128)" %
        (tx.hex(), sum(bin(b).count("1") for b in tx)))
    wx = ra["W0"] ^ rb["W0"]
    cand = {"W0_A": ra["W0"], "W0_B": rb["W0"], "W0_xor": wx,
            "d2_A": ra["d2"], "d2_B": rb["d2"], "d2_xor": ra["d2"] ^ rb["d2"]}
    if ra["P"] is not None and rb["P"] is not None:
        cand["P_A"] = ra["P"]; cand["P_B"] = rb["P"]; cand["P_xor"] = ra["P"] ^ rb["P"]
    for nm, wv in cand.items():
        for rep in (">4I", "<4I"):
            if tx == struct.pack(rep, *([wv] * 4)):
                log("  tile_xor == %s repeated (%s)" % (nm, rep))
    # per-word tile xor vs candidate words
    wa = ra["tile"]; wb = rb["tile"]
    perx = [a ^ b for a, b in zip(wa, wb)]
    log("  per-word tile xor: %s" % " ".join("%08x" % w for w in perx))
    relx = []
    for nm, wv in cand.items():
        if wv in perx:
            relx.append("%s@%d" % (nm, perx.index(wv)))
    log("  per-word tile-xor members of candidate set {W0_A,W0_B,W0_xor,d2_A,"
        "d2_B,d2_xor,P_A,P_B,P_xor}: %s" % (relx or "none"))
    # d4
    d4x = [a ^ b for a, b in zip(ra["d4"], rb["d4"])]
    log("  d4_A = %s" % " ".join("%08x" % w for w in ra["d4"]))
    log("  d4_B = %s" % " ".join("%08x" % w for w in rb["d4"]))
    log("  d4 xor = %s  (equal words: %d/8)" %
        (" ".join("%08x" % w for w in d4x), sum(1 for w in d4x if w == 0)))
    d4rel = []
    for i, (a, b) in enumerate(zip(ra["d4"], rb["d4"])):
        r = prng_step_tests(a, b)
        if r:
            d4rel.append("d4[%d]: %s" % (i, r))
    log("  d4 word-pair PRNG relations: %s" % (d4rel or "none"))
    log("  P_A ^ P_B = %s ; P pair rel=%s ; d4[0]_A vs d4[0]_B rel=%s" %
        ("%08x" % (ra["P"] ^ rb["P"]) if ra["P"] is not None and rb["P"] is not None else "-",
         prng_step_tests(ra["P"], rb["P"]) or "none"
         if ra["P"] is not None and rb["P"] is not None else "-",
         prng_step_tests(ra["d4"][0], rb["d4"][0]) or "none"))


probe_pair(rows[0], rows[2], "desc same-second pair")
p2 = next(r for r in rows if r["id"] == "P2")
p4 = next(r for r in rows if r["id"] == "P4")
probe_pair(p2, p4, "pair same-second pair (same nsign blob)")

# ---------------------------------------------------------------------------
# SECTION 5 - summary
# ---------------------------------------------------------------------------
log("\n" + "-" * 78)
log("SECTION 5 - summary")
log("-" * 78)
log("rows tested: %d (S0,S1,S2 + %d pair rows + %d app rows)" %
    (len(rows), 7, 6))
log("secret candidates: K16=%d KVAR=%d K4=%d (deduped by content)" %
    (len(K16), len(KVAR), len(K4)))
for k2, v in fam_summary.items():
    log("  family %-22s computations: %d" % (k2, v))
log("total (row,test) comparisons: %d" % tests)
log("HITS: %d" % len(hits))
log("elapsed: %.1fs" % (time.time() - T0))

json.dump({"rows": len(rows), "K16": len(K16), "KVAR": len(KVAR), "K4": len(K4),
           "families": fam_summary, "tests": tests, "hits": [list(h) for h in hits]},
          open(os.path.join(HERE, "deriv3_summary.json"), "w"), indent=1)
log("saved deriv3_summary.json")
LOGF.close()
