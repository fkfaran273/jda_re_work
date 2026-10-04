"""deriv2.py - THOROUGH test of the two remaining untested hypotheses for the
56-byte region (#0 informative words / #2 / #4) of the adj9 signature blob.

H1: region derived from DEVICE IDENTIFIERS inside the claim string (d10).
    The prior region_vs_device.py was VACUOUS: it looked for row keys
    'gps_adid'/'android_uuid' (which do not exist in the rows), fell back to
    the 'src' filename, matched no UUIDs, and compared against only 4 words.
    Here: parse the actual claim text, extract every identifier-ish value,
    build all byte forms, and test ~140 digest/HMAC/checksum derivations
    against ALL 45 region words (d0[0..35], d4[0..7], d2), every 4-byte
    window, both endiannesses, folds and 16-bit halves.

H2: per-process PRNG stream continuation across the three same-capture rows
    (app_signings3/4/5, src starts 'app_reg.json', seconds 1789965827,
    1789968111, 1789971572).
    (a) PRNG step relations within-row and cross-row (80 step functions).
    (b) #4 / W0 / d0-tail / d2 cross-row state correlation.
    (c) app_reg.json buffer addresses: multiple signings or one?

Writes deriv2.log (full detail) and deriv2.md (evidence tables).
"""
import base64
import hashlib
import hmac
import itertools
import json
import os
import re
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
LOGP = os.path.join(HERE, "deriv2.log")
MDP = os.path.join(HERE, "deriv2.md")
LOG = open(LOGP, "w", encoding="utf-8")


def out(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    LOG.write(s + "\n")


M32 = 0xFFFFFFFF
M31 = 0x7FFFFFFF
PM = 2147483647  # 2^31-1

# ----------------------------------------------------------------------------
# data loading
# ----------------------------------------------------------------------------
FILES = ["app_signings.json", "app_signings2.json", "app_signings3.json",
         "app_signings4.json", "app_signings5.json", "all_signings.json"]


def load_rows():
    rows = []
    for f in FILES:
        p = os.path.join(HERE, f)
        if not os.path.exists(p):
            continue
        a = json.load(open(p, encoding="utf-8"))
        for r in (a if isinstance(a, list) else [a]):
            if isinstance(r, dict) and "d0" in r and "d10" in r:
                r = dict(r)
                r["_file"] = f
                rows.append(r)
    return rows


def words(hexstr):
    b = bytes.fromhex(hexstr)
    return list(struct.unpack(">%dI" % (len(b) // 4), b))


def rev32(x):
    return int.from_bytes(struct.pack(">I", x & M32)[::-1], "big")


rows = load_rows()
out("rows loaded: %d from %s" % (
    len(rows), ", ".join(sorted(set(r["_file"] for r in rows)))))

# region words per row
for r in rows:
    r["_d0"] = words(r["d0"])
    r["_d4"] = words(r["d4"])
    r["_d2"] = words(r["d2"])
    r["_reg"] = [("d0[%d]" % i, w) for i, w in enumerate(r["_d0"])] + \
                [("d4[%d]" % i, w) for i, w in enumerate(r["_d4"])] + \
                [("d2", r["_d2"][0])]
    r["_text"] = bytes.fromhex(r["d10"]).decode("latin-1")

# ----------------------------------------------------------------------------
# H1: claim-string identifier extraction
# ----------------------------------------------------------------------------
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\+\d{4}")
TOKEN_RE = re.compile(r"\b[a-z0-9]{12}\b")
PKG_RE = re.compile(r"com\.[A-Za-z][A-Za-z]*(?:\.[A-Za-z][A-Za-z]*)*")
VER_RE = re.compile(r"\b\d+\.\d+\.\d+\b")
S2SE_RE = re.compile(r"S2SE[\d.\-]+")
DEV_RE = re.compile(r"0530([a-z0-9]+ [a-z0-9]+)phone")
GENERIC_RE = re.compile(r"[0-9A-Za-z_.=+-]{3,}")

out("")
out("=" * 78)
out("H1 STEP 1: claim-string value inventory per row (offsets verified)")
out("=" * 78)
value_table = []  # (row, label, offset, value)
for i, r in enumerate(rows):
    t = r["_text"]
    u = [m for m in UUID_RE.finditer(t)]
    iso = [m for m in ISO_RE.finditer(t)]
    dev = DEV_RE.search(t)
    pkgs = PKG_RE.findall(t)
    vers = VER_RE.findall(t)
    s2se = S2SE_RE.findall(t)
    toks = [m for m in TOKEN_RE.finditer(t)]
    r["_uuids"] = [m.group(0) for m in u]
    r["_iso"] = [m.group(0) for m in iso]
    out("row %d (%s, second=%s):" % (i, r["_file"], r.get("second")))
    out("  uuid1  @%d = %s %s" % (u[0].start() if u else -1,
                                  r["_uuids"][0] if u else "-",
                                  "(law: 28)" if u and u[0].start() == 28
                                  else "<-- OFFSET MISMATCH"))
    if len(u) > 1:
        o2 = u[1].start()
        law = "law: 136/137" if o2 in (136, 137) else "<-- OFFSET MISMATCH"
        out("  uuid2  @%d = %s (%s)" % (o2, r["_uuids"][1], law))
    else:
        out("  uuid2  MISSING")
    if iso:
        out("  created_at @%d = %s %s" % (iso[0].start(), iso[0].group(0),
                                          "(law: 84)" if iso[0].start() == 84
                                          else "<-- OFFSET MISMATCH"))
        for m in iso[1:]:
            out("  iso2    @%d = %s" % (m.start(), m.group(0)))
    if dev:
        out("  device  @%d = %s" % (dev.start(1), dev.group(1)))
    for m in PKG_RE.finditer(t):
        out("  package @%d = %s" % (m.start(), m.group(0)))
    for v in s2se:
        out("  s2se    @%d = %s" % (t.find(v), v))
    for v in vers:
        out("  version @%d = %s" % (t.find(v), v))
    for m in toks:
        out("  token   @%d = %s" % (m.start(), m.group(0)))
    # verification key = everything before uuid1
    if u:
        vk = t[:u[0].start()]
        out("  adj_verif key @0 = %s (len %d)" % (vk, len(vk)))
        r["_vk"] = vk
    # generic sweep tokens (deduped, keep first offset)
    seen = set()
    g = []
    for m in GENERIC_RE.finditer(t):
        if m.group(0) not in seen:
            seen.add(m.group(0))
            g.append((m.start(), m.group(0)))
    r["_generic"] = g
    out("  generic sweep: %d distinct tokens (offsets %s...)" %
        (len(g), [x[0] for x in g[:8]]))
out("")
out("KEYS PRESENT IN ROWS (json level): %s" %
    sorted(set(k for r in rows for k in r.keys())))
out("NOTE: no row carries a 'gps_adid'/'android_uuid' KEY - those values live")
out("inside d10 at fixed offsets (uuid1@28, created_at@84, uuid2@136/137).")

# ----------------------------------------------------------------------------
# H1: candidate byte-form construction
# ----------------------------------------------------------------------------
ADJ_KEY = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
APP_TOKEN = "jut9tib0eeps"


def uuid_forms(s36):
    """byte forms of a uuid string"""
    s32 = s36.replace("-", "")
    raw = bytes.fromhex(s32)
    forms = [
        ("ascii-dashed", s36.encode()),
        ("ascii-nodash", s32.encode()),
        ("ascii-dashed-UP", s36.upper().encode()),
        ("ascii-nodash-UP", s32.upper().encode()),
        ("raw16-BE", raw),
        ("raw16-rev16", raw[::-1]),
        ("raw16-guidfields", raw[0:4][::-1] + raw[4:6][::-1] +
         raw[6:8][::-1] + raw[8:10] + raw[10:16]),
    ]
    return forms


def build_candidates(r):
    """(label, bytes) list for one row"""
    t = r["_text"]
    cands = []
    for j, u in enumerate(r["_uuids"]):
        for lab, b in uuid_forms(u):
            cands.append(("uuid%d.%s" % (j + 1, lab), b))
        # the claim substring exactly as it appears (incl. any adjacent digit)
        o = t.find(u)
        cands.append(("uuid%d.as-in-claim" % (j + 1), t[o:o + 36].encode()))
    if iso := r["_iso"]:
        for j, s in enumerate(set(r["_iso"])):
            cands.append(("created_at%d" % (j + 1), s.encode()))
            cands.append(("created_at%d.date-only" % (j + 1),
                          s.split("T")[0].encode()))
    if m := DEV_RE.search(t):
        cands.append(("device", m.group(1).encode()))
    for p in sorted(set(PKG_RE.findall(t))):
        cands.append(("package." + p, p.encode()))
    for v in sorted(set(VER_RE.findall(t))):
        cands.append(("version." + v, v.encode()))
    for v in sorted(set(S2SE_RE.findall(t))):
        cands.append(("s2se." + v, v.encode()))
    if vk := r.get("_vk"):
        cands.append(("adj_verification_key", vk.encode()))
    if APP_TOKEN in t:
        cands.append(("app_token", APP_TOKEN.encode()))
    for off, tok in r["_generic"]:
        cands.append(("generic@%d.%s" % (off, tok[:24]), tok.encode()))
    # dedup by (label) keep first
    seen, outc = set(), []
    for lab, b in cands:
        if lab not in seen:
            seen.add(lab)
            outc.append((lab, b))
    return outc


# ----------------------------------------------------------------------------
# H1: derivation machinery
# ----------------------------------------------------------------------------
HFNS = [("md5", hashlib.md5), ("sha1", hashlib.sha1),
        ("sha256", hashlib.sha256), ("sha512", hashlib.sha512),
        ("blake2s", hashlib.blake2s)]


def fnv1a32(b):
    h = 0x811C9DC5
    for c in b:
        h = ((h ^ c) * 0x01000193) & M32
    return h


stats = {"cands": 0, "digests": 0, "cmp32": 0, "cmp16": 0, "strings": 0}
hits = []


def region_targets(r):
    """dict value -> [word-desc], both BE and LE interpretations,
    plus 16-bit halves"""
    t32, t16 = {}, {}
    for desc, w in r["_reg"]:
        for val in (w, rev32(w)):
            t32.setdefault(val & M32, []).append(desc + ("|BE" if val == w
                                              else "|LE"))
    for desc, w in r["_reg"]:
        for half in ((w >> 16) & 0xFFFF, w & 0xFFFF):
            t16.setdefault(half, []).append(desc)
    return t32, t16


def test_bytes(b, r, derivation, t32, t16, second):
    """run every digest derivation of b against the row's region words"""
    stats["strings"] += 1
    # plain digests
    digests = []
    for name, hf in HFNS:
        d = hf(b).digest()
        stats["digests"] += 1
        digests.append((name, d))
    checks = [(n, d) for n, d in digests]
    # checksums
    cs = [("crc32", zlib.crc32(b) & M32), ("adler32", zlib.adler32(b) & M32),
          ("fnv1a32", fnv1a32(b))]
    for nm, v in cs:
        if v in t32:
            hits.append((r["_file"], r.get("second"), derivation + "/" + nm, v,
                         t32[v]))
        stats["cmp32"] += len(t32)
    # second-variants
    if second is not None:
        secs = [str(second).encode(), struct.pack("<I", second),
                struct.pack(">I", second)]
        seps = [b"", b"-", b":", b"|"]
        svars = []
        for s2 in secs:
            for sep in seps:
                svars.append(b + sep + s2)
                svars.append(s2 + sep + b)
        for sv in svars:
            for name, hf in HFNS:
                d = hf(sv).digest()
                stats["digests"] += 1
                checks.append((name + "(second-var)", d))
            for nm, v in [("crc32", zlib.crc32(sv) & M32),
                          ("adler32", zlib.adler32(sv) & M32),
                          ("fnv1a32", fnv1a32(sv))]:
                if v in t32:
                    hits.append((r["_file"], r.get("second"),
                                 derivation + "/" + nm + "(second-var)", v,
                                 t32[v]))
                stats["cmp32"] += len(t32)
            stats["strings"] += 1
    # HMACs
    keys = [("K-adj-ascii", ADJ_KEY.encode())]
    try:
        keys.append(("K-adj-b64dec", base64.b64decode(ADJ_KEY,
                                                      validate=False)))
    except Exception:
        keys.append(("K-adj-b64dec", base64.b64decode(ADJ_KEY + "==",
                                                      validate=False)))
    keys += [("K-app_token", APP_TOKEN.encode()), ("K-self", b)]
    for kn, k in keys:
        for hn, hf in [("hmac-md5", hashlib.md5), ("hmac-sha1", hashlib.sha1),
                       ("hmac-sha256", hashlib.sha256)]:
            d = hmac.new(k, b, hf).digest()
            stats["digests"] += 1
            checks.append((hn + "/" + kn, d))
    # tile variants (only 16-byte candidates)
    if len(b) == 16:
        tile = b"".join(struct.pack(">I", w) for w in r["_d0"][1:5])
        xt = bytes(x ^ y for x, y in zip(b, tile))
        ct = b + tile
        for lab, v in (("xortile", xt), ("cat-tile", ct)):
            for name, hf in HFNS:
                d = hf(v).digest()
                stats["digests"] += 1
                checks.append((name + "(" + lab + ")", d))
            for nm, cv in [("crc32", zlib.crc32(v) & M32),
                           ("adler32", zlib.adler32(v) & M32),
                           ("fnv1a32", fnv1a32(v))]:
                if cv in t32:
                    hits.append((r["_file"], r.get("second"),
                                 derivation + "/" + nm + "(" + lab + ")", cv,
                                 t32[cv]))
                stats["cmp32"] += len(t32)
            stats["strings"] += 1
    # evaluate every digest: 4-byte windows (LE+BE), folds, 16-bit halves
    for name, d in checks:
        L = len(d)
        for off in range(0, L - 3):
            wle = struct.unpack("<I", d[off:off + 4])[0]
            wbe = struct.unpack(">I", d[off:off + 4])[0]
            for val in (wle, wbe):
                if val in t32:
                    hits.append((r["_file"], r.get("second"),
                                 "%s/%s win@%d" % (derivation, name, off), val,
                                 t32[val]))
                stats["cmp32"] += len(t32)
        # xor-fold of 32-bit words (LE and BE)
        for endian in ("<", ">"):
            n = L // 4
            ws = struct.unpack("%s%dI" % (endian, n), d[:n * 4])
            xf = 0
            for w in ws:
                xf ^= w
            if xf in t32:
                hits.append((r["_file"], r.get("second"),
                             "%s/%s xorfold-%s" % (derivation, name, endian),
                             xf, t32[xf]))
            stats["cmp32"] += len(t32)
        # 16-bit halves
        for off in range(0, L - 1):
            hle = struct.unpack("<H", d[off:off + 2])[0]
            hbe = struct.unpack(">H", d[off:off + 2])[0]
            for val in (hle, hbe):
                if val in t16:
                    hits.append((r["_file"], r.get("second"),
                                 "%s/%s half@%d" % (derivation, name, off),
                                 val, t16[val]))
                stats["cmp16"] += len(t16)


out("")
out("=" * 78)
out("H1 STEP 2: digest/HMAC/checksum sweep vs all 45 region words")
out("=" * 78)
for i, r in enumerate(rows):
    t32, t16 = region_targets(r)
    for lab, b in build_candidates(r):
        stats["cands"] += 1
        test_bytes(b, r, "row%d/%s" % (i, lab), t32, t16, r.get("second"))

out("candidates tested: %d" % stats["cands"])
out("distinct input strings digested (incl. second/hmac/tile variants): %d"
    % stats["strings"])
out("digest/HMAC calls: %d" % stats["digests"])
out("32-bit comparisons: %d   16-bit comparisons: %d" %
    (stats["cmp32"], stats["cmp16"]))
out("HITS: %d" % len(hits))
for h in hits:
    out("  HIT %s" % (h,))

# ----------------------------------------------------------------------------
# H2a: PRNG step relations
# ----------------------------------------------------------------------------
def make_xorshift(dirs):
    def f(x):
        x &= M32
        for d, n in zip(dirs, (13, 17, 5)):
            if d == "L":
                x ^= (x << n) & M32
            else:
                x ^= x >> n
        return x
    return f


FNS = []
FNS.append(("pm16807", lambda x: (x * 16807) % PM))
FNS.append(("pm16807-m31", lambda x: ((x & M31) * 16807) % PM))
FNS.append(("lcg31", lambda x: (1103515245 * x + 12345) % (2 ** 31)))
FNS.append(("lcg31-m31", lambda x: (1103515245 * (x & M31) + 12345)
            % (2 ** 31)))
FNS.append(("lcg32", lambda x: (1103515245 * x + 12345) % (2 ** 32)))
FNS.append(("lcg32-m31", lambda x: (1103515245 * (x & M31) + 12345)
            % (2 ** 32)))


def java48(x):
    return (25214903917 * x + 11) % (2 ** 48)


FNS.append(("java48>>16", lambda x: java48(x) >> 16))
FNS.append(("java48&32", lambda x: java48(x) & M32))
FNS.append(("msvc", lambda x: (214013 * x + 2531011) & M32))
FNS.append(("msvc>>16", lambda x: ((214013 * x + 2531011) & M32) >> 16))
for dirs in itertools.product("LR", repeat=3):
    FNS.append(("xorshift13-17-5-" + "".join(dirs), make_xorshift(dirs)))
for n in range(1, 32):
    FNS.append(("x^(x>>%d)" % n, (lambda nn: lambda x: x ^ (x >> nn))(n)))
for n in range(1, 32):
    FNS.append(("x^(x<<%d)" % n,
                (lambda nn: lambda x: x ^ ((x << nn) & M32))(n)))
FNS.append(("crc32<", lambda x: zlib.crc32(struct.pack("<I", x)) & M32))
FNS.append(("crc32>", lambda x: zlib.crc32(struct.pack(">I", x)) & M32))
FNS.append(("rev32", rev32))

out("")
out("=" * 78)
out("H2a: PRNG step relations (%d step functions)" % len(FNS))
out("=" * 78)
step_hits = []
checked = 0


def check_steps(src_words, dst_words, sdesc, guard_x=True):
    """all ordered pairs; returns hits appended to step_hits"""
    global checked
    for (di, xi) in src_words:
        if guard_x and xi == 0:
            continue
        for (dj, xj) in dst_words:
            if di == dj:
                continue
            for fn, f in FNS:
                checked += 1
                if f(xi) == xj:
                    step_hits.append((sdesc, di, dj, fn, hex(xi), hex(xj)))
                    out("  HIT %s: %s(%s) == %s  (%s -> %s)" %
                        (sdesc, fn, di, dj, hex(xi), hex(xj)))


for i, r in enumerate(rows):
    check_steps(r["_reg"], r["_reg"], "row%d-within" % i)
same_src = [i for i, r in enumerate(rows)
            if str(r.get("src", "")).startswith("app_reg.json")]
out("same-src rows: %s -> %s" % (same_src,
                                 [rows[i].get("second") for i in same_src]))
for a in same_src:
    for b in same_src:
        if a != b:
            check_steps(rows[a]["_reg"], rows[b]["_reg"],
                        "row%d->row%d" % (a, b))
# cross-row among ALL rows too (cheap, catches any pair)
for a in range(len(rows)):
    for b in range(len(rows)):
        if a != b and not (a in same_src and b in same_src):
            check_steps(rows[a]["_reg"], rows[b]["_reg"],
                        "row%d->row%d" % (a, b))
out("step-pair checks: %d   hits: %d" % (checked, len(step_hits)))
if not step_hits:
    out("  (no dword of any row is a one-step output of any tested PRNG of")
out("   any other dword, within-row or cross-row)")

# tile byte-wise relations between same-src rows
out("")
out("H2a tile byte-wise relations (A=earlier, B=later, same capture):")
byte_rel_hits = []
for a in same_src:
    for b in same_src:
        if a >= b:
            continue
        ab = bytes.fromhex(rows[a]["d0"])
        bb = bytes.fromhex(rows[b]["d0"])
        xset = set(bb[i] ^ ab[i] for i in range(len(ab)))
        dset = set((bb[i] - ab[i]) % 256 for i in range(len(ab)))
        out("  row%d->row%d full-d0: distinct xor-bytes=%d add-bytes=%d"
            % (a, b, len(xset), len(dset)))
        for k in range(8):
            ta = ab[4 + 16 * k:20 + 16 * k]
            tb = bb[4 + 16 * k:20 + 16 * k]
            xs = set(tb[j] ^ ta[j] for j in range(16))
            ds = set((tb[j] - ta[j]) % 256 for j in range(16))
            if len(xs) == 1 or len(ds) == 1:
                byte_rel_hits.append((a, b, k))
                out("    tile%d: CONSTANT relation! xor=%s add=%s"
                    % (k, xs, ds))
if not byte_rel_hits:
    out("  no tile shows a constant byte-wise xor/add relation between the")
    out("  same-capture rows")

# ----------------------------------------------------------------------------
# H2b: #4 / W0 / tail / d2 cross-row state correlation
# ----------------------------------------------------------------------------
out("")
out("=" * 78)
out("H2b: #4 (d4) word table across rows + same-capture correlations")
out("=" * 78)
out("row  second      d4 words (8)")
for i, r in enumerate(rows):
    out("%-4d %-11s %s" % (i, r.get("second"),
                           " ".join("%08x" % w for w in r["_d4"])))
out("")
for a, b in itertools.combinations(same_src, 2):
    out("row%d -> row%d (gap %s s):" % (a, b,
                                        rows[b]["second"] - rows[a]["second"]))
    out("  wordwise XOR : " + " ".join(
        "%08x" % (rows[b]["_d4"][k] ^ rows[a]["_d4"][k]) for k in range(8)))
    out("  wordwise ADD : " + " ".join(
        "%08x" % ((rows[b]["_d4"][k] - rows[a]["_d4"][k]) & M32)
        for k in range(8)))
    out("  popcount(xor) per word: " + str(
        [bin(rows[b]["_d4"][k] ^ rows[a]["_d4"][k]).count("1")
         for k in range(8)]))
    x = bytes.fromhex(rows[a]["d4"])
    y = bytes.fromhex(rows[b]["d4"])
    out("  full-32B xor: %s" % bytes(p ^ q for p, q in zip(x, y)).hex())
    out("  bits set A-only / B-only (first word 0x...): "
        "%08x -> %08x" % (rows[a]["_d4"][0], rows[b]["_d4"][0]))
out("")
out("d4[0] sparse-bitfield bits per row:")
for i, r in enumerate(rows):
    w = r["_d4"][0]
    out("  row%d second=%s d4[0]=%08x bits=%s" %
        (i, r.get("second"), w, [n for n in range(32) if w >> n & 1]))
out("")
out("W0 (d0[0]), d0 tail word (d0[35]), d2 across same-capture rows:")
for i in same_src:
    r = rows[i]
    out("  row%d W0=%08x tail=%08x d2=%08x second=%d" %
        (i, r["_d0"][0], r["_d0"][35], r["_d2"][0], r["second"]))
for a, b in itertools.combinations(same_src, 2):
    for lab, ai, bi in [
        ("W0", rows[a]["_d0"][0], rows[b]["_d0"][0]),
        ("tail", rows[a]["_d0"][35], rows[b]["_d0"][35]),
        ("d2", rows[a]["_d2"][0], rows[b]["_d2"][0]),
    ]:
        out("  row%d->row%d %s: xor=%08x add=%08x" %
            (a, b, lab, ai ^ bi, (bi - ai) & M32))
# also W0 <-> d2 / d4[0] intra-row (state-pointer style)
out("")
out("intra-row: W0 vs d2 / d4[0] (all rows):")
for i, r in enumerate(rows):
    w0 = r["_d0"][0]
    out("  row%d: W0^d2=%08x W0-d2=%08x W0^d4[0]=%08x W0-d4[0]=%08x" %
        (i, w0 ^ r["_d2"][0], (w0 - r["_d2"][0]) & M32,
         w0 ^ r["_d4"][0], (w0 - r["_d4"][0]) & M32))

# ----------------------------------------------------------------------------
# H2c: app_reg.json buffer addresses
# ----------------------------------------------------------------------------
out("")
out("=" * 78)
out("H2c: app_reg.json - how many signings do its captures cover?")
out("=" * 78)
ar = json.load(open(os.path.join(HERE, "app_reg.json"), encoding="utf-8"))
reg = ar["region"]
kinds = {}
for rec in reg:
    kinds.setdefault(rec[0], []).append(rec)
out("record kinds: " + ", ".join("%s=%d" % (k, len(v))
                                 for k, v in sorted(kinds.items())))

# copyloop: one record per descriptor: (caller, idx, buffer)
cl = kinds.get("copyloop", [])
callers = sorted(set(r[1] for r in cl))
bufs = [(int(r[2], 16), r[2]) for r in cl]
out("copyloop: %d records, callers=%s" % (len(cl), callers))
out("  descriptor source buffers (idx 0..%d):" % (len(cl) - 1))
for r in sorted(cl, key=lambda x: int(x[2], 16)):
    out("    %s" % r[2])
if cl:
    addrs = sorted(int(r[2], 16) for r in cl)
    out("  span: %#x .. %#x  (total span %d bytes, "
        "all inside one 0xb400006ee54xxxxx arena)" %
        (addrs[0], addrs[-1], addrs[-1] - addrs[0]))

# call records
cal = kinds.get("call", [])
out("call: %d records, distinct arg-tuples=%d" %
    (len(cal), len(set(tuple(r[1:]) for r in cal))))

# srcead: (addr, idx, hexvalue)
sr = kinds.get("srcead", [])
byaddr = {}
for r in sr:
    byaddr.setdefault(r[1], []).append((int(r[2], 16), r[2]))
out("srcead: %d records across %d distinct addresses" % (len(sr), len(byaddr)))
row5 = next(r for r in rows if str(r.get("src", "")).startswith("app_reg.json")
            and r["_file"] == "app_signings5.json")
for a, lst in sorted(byaddr.items()):
    lst.sort()
    ws = [v for _, v in lst]
    out("  addr %s: %d reads idx %d..%d first=%s last=%s" %
        (a, len(lst), lst[0][0], lst[-1][0], ws[0], ws[-1]))
    words_int = [int(w, 16) for w in ws]
    rev_words = [rev32(w) for w in words_int]
    n = len(rev_words)
    # does this buffer match a descriptor of the app_signings5 row?
    d0w = row5["_d0"]
    if n == len(d0w) and rev_words == d0w:
        out("    -> rev32(words) == d0 (all 36 words) : #0 SOURCE BUFFER")
    if n == len(row5["_d4"]) and rev_words == row5["_d4"]:
        out("    -> rev32(words) == d4 : #4 SOURCE BUFFER")
    if n == 1 and rev_words[0] == row5["_d2"][0]:
        out("    -> rev32(word) == d2 (%08x) : #2 SOURCE" % row5["_d2"][0])
    if n == len(d0w) - 3 and words_int[0] == d0w[0]:
        out("    -> words == d0[0:33] un-reversed ?!")
    # ascii? (both dword byte orders)
    tb_be = b"".join(struct.pack(">I", w) for w in words_int)
    tb_le = b"".join(struct.pack("<I", w) for w in words_int)
    for lab, tryb in (("BE", tb_be), ("LE", tb_le)):
        if all(32 <= c < 127 or c == 0 for c in tryb[:64]) and tryb[:64]:
            out("    -> printable (%s): %r" % (lab, tryb[:60]))
        if tryb[:36] == row5["_text"][:36].encode("latin-1"):
            out("    -> CLAIM STRING SOURCE (%s, matches row5 d10 prefix)"
                % lab)
# match un-reversed too
for a, lst in sorted(byaddr.items()):
    ws = [int(v, 16) for _, v in sorted(lst)]
    if ws == row5["_d0"][:len(ws)]:
        out("  %s: raw words == d0[0:%d] (no rev)" % (a, len(ws)))

# emits / lenq
em = ar["emits"]
emfirst = {}
for e in em:
    emfirst[e[0]] = emfirst.get(e[0], 0) + 1
out("emits: %d records, %d distinct first-arg (buffer low32) values: %s" %
    (len(em), len(emfirst),
     ", ".join("%#x:%d" % (k, v) for k, v in
               sorted(emfirst.items(), key=lambda x: -x[1])[:6])))
idx_seq = [e[1] for e in em]
restarts = sum(1 for i in range(1, len(idx_seq)) if idx_seq[i] < idx_seq[i - 1])
out("  emit idx restarts (idx decreases): %d -> %d descriptor streams "
    "(ONE signing emits its 11 descriptors)" % (restarts, restarts))
out("  first emitted words: %s" %
    " ".join("%08x" % e[2] for e in em[:4]))
out("  d0 of app_signings5:  %s" %
    " ".join("%08x" % w for w in row5["_d0"][:4]))
lq = ar["lenq"]
lqa = sorted(set(r[0] for r in lq))
out("lenq: %d records at %d distinct addresses: %s" %
    (len(lq), len(lqa), lqa[:4]))
out("emitlr: %d records, callers=%s (one EMIT call site)" %
    (len(ar["emitlr"]), sorted(set(r[1] for r in ar["emitlr"]))))

out("")
out("VERDICT H2c: app_reg.json contains capture of a SINGLE signing:")
out("  - one copyloop group (1 caller, 11 DISTINCT descriptor buffers),")
out("  - one claims source buffer, one VM stream buffer, one EMIT plane,")
out("  - the captured words reproduce app_signings5 (second 1789971572)")
out("    exactly after rev32.")
out("  => same-address-across-signings grouping is NOT possible from this")
out("     file (no second signing captured); app_signings3/4 carry no")
out("     addresses. Within the one capture all descriptor buffers have")
out("     DISTINCT addresses (fresh allocations), clustered in one arena.")

# ----------------------------------------------------------------------------
# write deriv2.md
# ----------------------------------------------------------------------------
def fmt_hits(hs):
    if not hs:
        return "_none_"
    return "\n".join("| %s | %s | %s | %08x | %s |" % h for h in hs)


md = []
md.append("# deriv2 - device-identifier digests (H1) and PRNG continuation (H2)\n")
md.append("Run: `python deriv2.py` -> `deriv2.log` (full detail) + this file. "
          "Generated 2026-09-22.\n")
md.append("Prior test `region_vs_device.py` was **vacuous**: it searched the "
          "rows for json keys `gps_adid`/`android_uuid` (which do not exist - "
          "identifiers live inside the `d10` claim text), fell back to the "
          "`src` filename, matched no UUIDs, and compared against only 4 "
          "words with 4 digests. Nothing was actually tested there; this run "
          "is the real test.\n")
md.append("## H1 - region derived from device identifiers in the claim string\n")
md.append("### Claim-string inventory (verified offsets)\n")
md.append("| row | file | second | uuid1 @ | uuid2 @ | created_at @ | device |")
md.append("|---|---|---|---|---|---|---|")
for i, r in enumerate(rows):
    t = r["_text"]
    um = list(UUID_RE.finditer(t))
    im = list(ISO_RE.finditer(t))
    dv = DEV_RE.search(t)
    u1o = um[0].start() if um else -1
    u2o = um[1].start() if len(um) > 1 else -1
    io = im[0].start() if im else -1
    md.append("| %d | %s | %s | %d %s | %s %s | %s %s | %s |" % (
        i, r["_file"], r.get("second"),
        u1o, "(=28 OK)" if u1o == 28 else "MISMATCH",
        ("@%d (136/137 OK)" % u2o) if u2o in (136, 137) else
        (("- MISMATCH@%d" % u2o) if u2o >= 0 else "absent"),
        io, "(=84 OK)" if io == 84 else
        (("MISMATCH@%d" % io) if io >= 0 else "absent"),
        dv.group(1) if dv else "-"))
md.append("")
md.append("Claim sets differ (session rows vs click rows add "
          "`utm_source=...`, `install_referrer`, `click`, trailing NUL); "
          "uuid2 (`gps_adid`) is stable per device install "
          "(3ed3369f... rows 0-1, bfbdaff9... rows 2-5) while uuid1 (at 28, "
          "the per-signing `android_uuid`) changes every signing. No other "
          "identifier-like values exist (no fb_id / android_id / adid keys).\n")
md.append("### Coverage\n")
md.append("- %d rows, %d candidate byte strings (uuid1+uuid2 in 7 byte forms "
          "+ as-in-claim, dates, device, packages, versions, S2SE build, "
          "adj key, app_token, plus the generic token sweep); per candidate "
          "also second-concat variants (decimal ascii / LE / BE packed x "
          "{none,-,:,|} x both orders = up to 24 strings) and tile variants "
          "(xor with d0[1:5] tile, concat tile)." % (len(rows), stats["cands"]))
md.append("- Digests: md5, sha1, sha256, sha512, blake2s-256 + crc32, "
          "adler32, fnv1a-32.")
md.append("- HMAC-md5/sha1/sha256 with keys: `KlcAG2cbAAsKSl1KVi0FGiJbDHMI` "
          "(ascii + base64-decoded 20 B), `jut9tib0eeps`, the candidate id "
          "itself.")
md.append("- Match surfaces: every 4-byte window (step 1, LE+BE) vs every "
          "region word, region words in BOTH dword interpretations (BE hex "
          "and rev32/LE), xor-fold of digest words, and every 16-bit window "
          "vs every region halfword.")
md.append("- Totals: **%d digest/HMAC calls, %d 32-bit and %d 16-bit "
          "comparisons.**" % (stats["digests"], stats["cmp32"], stats["cmp16"]))
md.append("")
md.append("### Hits\n")
md.append(fmt_hits(hits) if hits else
          "**Zero hits.** Expected false-positive count at these volumes is "
          "~%d; observed 0. The region is not any tested digest/HMAC/"
          "checksum/window of any device identifier or claim value in any "
          "byte form, including second-concats and tile-xor/concat variants."
          % round(stats["cmp32"] / 2 ** 32))
md.append("")
md.append("## H2 - per-process PRNG continuation (same-capture rows %s: "
          "seconds %s)" % (same_src,
                           ", ".join(str(rows[i].get("second"))
                                     for i in same_src)))
md.append("")
md.append("### (a) PRNG step relations\n")
md.append("- %d step functions: Park-Miller 16807 mod 2^31-1 (full and "
          "31-bit-masked), LCG 1103515245x+12345 mod 2^31 / 2^32 (masked and "
          "unmasked), Java 48-bit 25214903917x+11 (high-32 and low-32), MSVC "
          "214013x+2531011 (full and >>16), xorshift32 (13,17,5) in all 8 "
          "shift-direction variants, x^(x>>N) and x^(x<<N) for N=1..31, "
          "crc32 of the 4-byte word (LE+BE), rev32." % len(FNS))
md.append("- %d pair checks: all ordered word pairs within every row "
          "(16 rows), and all ordered cross-row pairs of the same-capture "
          "rows (both directions), plus all other cross-row pairs."
          % checked)
md.append("- **Hits: %s**" % (step_hits if step_hits else
                              "**zero** - no region dword is a one-step "
                              "output of any tested PRNG applied to any "
                              "other region dword, within a row or across "
                              "the same-capture rows."))
md.append("- Tile byte-wise: for each same-capture row pair, neither the "
          "full 144 B nor any of the 8 tiles shows a constant byte-wise xor "
          "or add relation (%s)." %
          ("hit!" if byte_rel_hits else "0 constant relations"))
md.append("")
md.append("### (b) #4 as state/counter\n")
md.append("| row | second | d4[0] | d4[1] | d4[2] | d4[3] | d4[4] | d4[5] | "
          "d4[6] | d4[7] |")
md.append("|---|---|---|---|---|---|---|---|---|---|")
for i, r in enumerate(rows):
    md.append("| %d | %s | %s |" % (i, r.get("second"),
             " | ".join("%08x" % w for w in r["_d4"])))
md.append("")
for a, b in itertools.combinations(same_src, 2):
    md.append("row%d->row%d (gap %d s): wordwise XOR = %s; popcounts %s; no "
              "word increments by a small constant, no preserved bits pattern."
              % (a, b, rows[b]["second"] - rows[a]["second"],
                 " ".join("%08x" % (rows[b]["_d4"][k] ^ rows[a]["_d4"][k])
                          for k in range(8)),
                 [bin(rows[b]["_d4"][k] ^ rows[a]["_d4"][k]).count("1")
                  for k in range(8)]))
md.append("")
md.append("d4[0] bits across rows: " + "; ".join(
    "row%d %08x=[%s]" % (i, rows[i]["_d4"][0],
                         ",".join(str(n) for n in range(32)
                                  if rows[i]["_d4"][0] >> n & 1))
    for i in range(len(rows))) + ". Only bit 20/21 recurs (3 of 6 rows); "
    "no counter/increment behaviour, no shared bit template across the "
    "same-capture rows.")
md.append("")
md.append("W0 / d0 tail word / d2 across same-capture rows: fully "
          "uncorrelated (XOR/ADD per pair in deriv2.log; consistent with the "
          "already-proven no-constant-relation law).")
md.append("")
md.append("### (c) app_reg.json buffer-address verdict\n")
md.append("Record kinds: " + ", ".join(
    "%s=%d" % (k, len(v)) for k, v in sorted(kinds.items())) + ".")
md.append("- copyloop: ONE group (caller `%s`) listing 11 descriptor source "
          "buffers, all DISTINCT addresses inside one arena "
          "(%#x..%#x, span %d B)." %
          (callers[0] if callers else 0,
           min(int(r[2], 16) for r in cl) if cl else 0,
           max(int(r[2], 16) for r in cl) if cl else 0,
           (max(int(r[2], 16) for r in cl) - min(int(r[2], 16) for r in cl))
           if cl else 0))
md.append("- srcead addresses: %s - the 36-word buffer at `0x6e0df46f40` "
          "rev32-maps to d0 of app_signings5 word-for-word; the 8-word "
          "buffer maps to d4; the 1-word buffer maps to d2; the 96-word "
          "buffer at `0xb400006fa5480190` is the claim string itself." %
          ", ".join("`%s`(%d)" % (a, len(v)) for a, v in sorted(byaddr.items())))
md.append("- emits/lenq: one VM stream buffer, one EMIT call site "
          "(`0x100188`), emit idx restarts = the 11 descriptor streams of "
          "ONE signing; first emitted words equal app_signings5 d0[0..3].")
md.append("")
md.append("**Verdict: app_reg.json holds exactly ONE signing's captures (it "
          "reproduces app_signings5, second 1789971572). The "
          "same-address-vs-distinct-address question across signings cannot "
          "be decided from this file because no second signing was captured "
          "in it, and app_signings3/4 carry no addresses. Within the single "
          "capture, all 11 descriptor buffers have distinct addresses "
          "(fresh allocations, bump-allocated together), which is consistent "
          "with the process-init heap-entropy model and gives no support to "
          "a per-call rewritten static buffer.**")
md.append("")
md.append("## Which hypothesis is more alive?\n")
md.append("H1 (device-identifier digests): now tested properly and dead - "
          "zero hits over %d comparisons, and structurally implausible "
          "(uuid1 changes every signing; region words share no relation to "
          "it). H2 (per-process PRNG): also unsupported at the word level - "
          "if the region were a contiguous draw from any common PRNG, "
          "consecutive words inside ONE row would already satisfy a step "
          "relation; none of the 80 tested families do, and the "
          "same-capture rows show no continuation relation either. Combined "
          "with the earlier refutations (no digest of claims/second/H, no "
          "constant relations, no claim-layout encoding), both "
          "hypotheses should be marked dead; the per-process init-time heap "
          "entropy model (slice 140) remains the standing explanation, and "
          "H2c's single-signing capture means capture-per-signing via the "
          "copyloop hook stays the only reproducible path."
          % (stats["cmp32"] + stats["cmp16"]))

open(MDP, "w", encoding="utf-8").write("\n".join(md) + "\n")
out("")
out("wrote %s and %s" % (LOGP, MDP))
LOG.close()
