"""corpus_seed.py — empirical cryptanalysis on the captured signing corpus.

Corpora:
  FRESH  device/java_dump/signings_extract.json  3 signings, one process,
         one device (moto g42, widthPixels=1080 heightPixels=2237): canonical
         bytes (d3.a out), H (32-B TEE HMAC), 192-B wire blob, ts (ms).
  PROBE  device/java_dump/adj9_capture_run1.log type=probe_result — the oracle
         suite (Hook.java oracleSuite): 9 re-signings with controlled inputs:
           A1/A2  identical map+H+lvl (fresh clones)          (baseline x2)
           B1/B2  identical, H zeroed                         (baseline x2)
           C1     H[0] ^= 1
           D1/D2  first map value (gps_adid_attempt 1) -> "1X"
           E1     level=30 ; F1 level=31
  OLD    rev/all_signings.json (10 rows) + rev/desc_det_result.json (3 rows):
         the 147-dword region descriptors captured in-memory
         (d0=36 dw env telemetry [W0+tile x8+tail3], d9=5 dw cert SHA-1,
          d8=4 dw const, d4=8 dw, d2=1 dw, d7=1 dw claims-len,
          d10=claims bytes, d5=d6=0).

Sections:
  1. header inversion (Random3 law) + parse table
  2. region section parse + constant verification (old rows)
  3. constant / known-value window search in wire blobs and descriptors
  4. fresh pairwise XOR batteries + constant-XOR-across-signings tests
  5. oracle probe: same-second pairs, keystream structure
  6. old-corpus per-call isolation + PRNG kinship + time correlation

Usage: python corpus_seed.py   (from anywhere; paths absolute)
"""
import importlib.util
import json
import re
import struct
import sys
from datetime import datetime, timedelta

BASE = "C:/Users/Apps/Downloads/com.penti.app/adj9"
REV = BASE + "/rev"
JD = BASE + "/device/java_dump"

spec = importlib.util.spec_from_file_location("header_gen", REV + "/header_gen.py")
hg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hg)
make_header = hg.make_header
M31 = 2147483647

out_lines = []


def P(*a):
    s = " ".join(str(x) for x in a)
    out_lines.append(s)
    print(s)


def dw_be(b, off):
    return struct.unpack_from(">I", b, off)[0]


def dw_le(b, off):
    return struct.unpack_from("<I", b, off)[0]


def dwords(b):
    return [dw_be(b, i) for i in range(0, len(b) - 3, 4)]


def h32(v):
    return "%08x" % (v & 0xFFFFFFFF)


# ============================================================ 0. LOAD
P("=" * 78)
P("0. LOAD")
P("=" * 78)

fresh = json.load(open(JD + "/signings_extract.json", encoding="utf-8"))["signings"]
for r in fresh:
    r["canon"] = bytes.fromhex(r["canon_hex"])
    r["Hb"] = bytes.fromhex(r["H"])
    r["blob"] = bytes.fromhex(r["blob"])
    r["body"] = r["blob"][16:]
    r["hdr16"] = r["blob"][:16]

old = json.load(open(REV + "/all_signings.json", encoding="utf-8"))
ddet = json.load(open(REV + "/desc_det_result.json", encoding="utf-8"))

# oracle probe blobs from capture log
log = open(JD + "/adj9_capture_run1.log", encoding="utf-8", errors="replace").read()
m = re.search(r"###ADJ9_BEGIN type=probe_result.*?\ntext: (.*?)###ADJ9_END", log, re.S)
probe = {}
probe_stats = []
if m:
    blk = m.group(1)
    for nm, hx in re.findall(r"--\s+(\S+)\s+len=192\s*\n([0-9a-f]{384})", blk):
        probe[nm.strip()] = bytes.fromhex(hx)
    for ln in blk.splitlines():
        if ln.startswith(("#", "A1~", "B1~", "D1~", "A1~E", "A1~F", "hdr")) or " n_diff" in ln:
            probe_stats.append(ln)
P("fresh signings: %d   old region rows: %d   desc_det rows: %d   probe blobs: %d"
  % (len(fresh), len(old), len(ddet), len(probe)))
P("probe variants: %s" % ", ".join(probe.keys()))

# ============================================================ 1. HEADERS
P("")
P("=" * 78)
P("1. HEADER INVERSION (Random3 law) — wire blobs")
P("=" * 78)


def invert(hdr16, lo, hi):
    return [s for s in range(lo, hi) if make_header(s) == hdr16]


def msb_law(b):
    return sum(1 for i in range(0, len(b), 4) if b[i] < 0x80), len(b) // 4


P("%-10s %-33s %-11s %s" % ("blob", "header16", "second", "msb<80 (hdr)"))
rows_sec = {}
for r in fresh:
    name = "fresh%d" % r["n"]
    hits = invert(r["hdr16"], r["ts"] // 1000 - 10, r["ts"] // 1000 + 10)
    r["sec"] = hits[0] if len(hits) == 1 else (hits[0] if hits else None)
    rows_sec[name] = r["sec"]
    ok, tot = msb_law(r["hdr16"])
    P("%-10s %-33s %-11s %d/%d   hits=%s" %
      (name, r["hdr16"].hex(), r["sec"], ok, tot, hits))
probe_secs = {}
for nm, b in list(probe.items()):
    hits = invert(b[:16], 1790106100, 1790106130)
    sec = hits[0] if len(hits) == 1 else (hits[0] if hits else None)
    probe_secs[nm] = sec
    ok, tot = msb_law(b[:16])
    P("%-10s %-33s %-11s %d/%d   hits=%s" %
      (nm, b[:16].hex(), sec, ok, tot, hits))

# created_at interpretation check for fresh rows
P("")
P("fresh created_at vs ts:")
for r in fresh:
    cap = re.search(rb"created_at=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z\+(\d{4})", r["canon"])
    if cap:
        d = datetime.strptime(cap.group(1).decode(), "%Y-%m-%dT%H:%M:%S.%f")
        off = cap.group(2).decode()
        delta = timedelta(hours=int(off[:2]), minutes=int(off[2:]))
        epoch_loc = (d - delta).replace(tzinfo=None)
        epoch_utc = d.replace(tzinfo=None)
        ts_s = r["ts"] / 1000.0
        base = datetime(1970, 1, 1)
        e_loc = (epoch_loc - base).total_seconds()
        e_utc = (epoch_utc - base).total_seconds()
        pick = "local-offset" if abs(e_loc - ts_s) < 5 else ("as-UTC" if abs(e_utc - ts_s) < 5 else "?")
        P("  n=%d created_at=%s  epoch(local-offset)=%.3f  ts/1000=%.3f  -> %s (d=%.3f)"
          % (r["n"], cap.group(1).decode() + "+" + off, e_loc, ts_s, pick,
             min(abs(e_loc - ts_s), abs(e_utc - ts_s))))

# ============================================================ 2. REGION PARSE
P("")
P("=" * 78)
P("2. REGION SECTION PARSE (old rows) + CONSTANT VERIFICATION")
P("=" * 78)
SHA1_CONST = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
D8_CONST = bytes.fromhex("bffffffffffffd1f0007000000000000")


def words_of(hx):
    b = bytes.fromhex(hx) if isinstance(hx, str) else hx
    return dwords(b)


old_rows = []
for r in old:
    d0 = words_of(r["d0"])
    d4 = words_of(r["d4"])
    d8 = words_of(r["d8"])
    d9 = words_of(r["d9"])
    d2 = int(r["d2"], 16)
    d7 = int(r["d7"], 16)
    d10 = bytes.fromhex(r["d10"])
    d5 = int(r["d5"], 16)
    d6 = int(r["d6"], 16)
    tile = d0[2:6]                      # empirical: period-16 unit starts at word 2
    reps = all(d0[2 + 4 * k:6 + 4 * k] == tile for k in range(1, 8))
    tail = d0[34:36]
    row = {"src": r.get("src"), "ev": r.get("ev"), "d0": d0, "W0": d0[0],
           "w1": d0[1], "tile": tile, "reps_ok": reps, "tail": tail, "d2": d2, "d4": d4,
           "d7": d7, "d8": d8, "d9": d9, "d10": d10, "d5": d5, "d6": d6}
    # created_at -> second
    dts = re.findall(rb"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z\+(\d{4})", d10)
    sec = None
    if dts:
        d = datetime.strptime(dts[0][0].decode(), "%Y-%m-%dT%H:%M:%S.%f")
        off = dts[0][1].decode()
        delta = timedelta(hours=int(off[:2]), minutes=int(off[2:]))
        base = datetime(1970, 1, 1)
        e = (d - delta - base).total_seconds()
        sec = int(e) + 1           # HEADER_LAW: second = created_at floor + 1
    row["sec_est"] = sec
    row["ndates"] = len(dts)
    old_rows.append(row)

P("%-4s %-11s %-9s %-9s %-9s %-9s %-6s %-9s %-6s %-6s %-6s %-11s %s" %
  ("row", "src", "W0", "w1", "TILE0", "TILE1", "reps", "d2", "d7", "len10", "d9", "sec_est", "extra"))
for i, r in enumerate(old_rows):
    P("%-4d %-11s %-9s %-9s %-9s %-9s %-6s %-9s %-6d %-6d %-6s %-11d %s" %
      (i, (r["src"] or "?").replace("whcap_", "").replace(".json", "") + ("+%d" % r["ev"] if r["ev"] else ""),
       h32(r["W0"]), h32(r["w1"]), h32(r["tile"][0]), h32(r["tile"][1]),
       "8x" if r["reps_ok"] else "BAD", h32(r["d2"]), r["d7"], len(r["d10"]),
       "YES" if bytes(struct.pack(">5I", *r["d9"])) == SHA1_CONST else "NO",
       r["sec_est"],
       "w1==T3" if r["w1"] == r["tile"][3] else ("w1==T0" if r["w1"] == r["tile"][0] else "w1?")))

P("")
P("desc_det rows (sec explicit):")
for i, r in enumerate(ddet):
    d0 = r["d0"]
    tile = d0[2:6]
    reps = all(d0[2 + 4 * k:6 + 4 * k] == tile for k in range(1, 8))
    P("  S%d kind=%s sec=%d created_at=%s W0=%s w1=%s TILE=%s reps=%s tail=%s d2=%s d4=%s d7=%d d10=%d dw" %
      (i, r["kind"], r["sec"], r["created_at"], h32(d0[0]), h32(d0[1]),
       ",".join(h32(x) for x in tile), "8x" if reps else "BAD",
       ",".join(h32(x) for x in d0[34:36]),
       h32(r["d2"]), ",".join(h32(x) for x in r["d4"][:4]) + "..", r["d7"], r["d10"]))
P("  d9 all == SHA1_CONST: %s   d8 all == D8_CONST: %s   d5=d6=0 all: %s" %
  (all(bytes(struct.pack(">5I", *r["d9"])) == SHA1_CONST for r in old_rows),
   all(bytes(struct.pack(">4I", *r["d8"])) == D8_CONST for r in old_rows),
   all(r["d5"] == 0 and r["d6"] == 0 for r in old_rows)))
P("  d7 == unpadded len(d10) (len10 == d7 rounded up to 4): %s" %
  all(len(r["d10"]) == (r["d7"] + 3) // 4 * 4 for r in old_rows))
P("  tile repetition 8x (words 2..33) + tail(34..35)==TILE[0:2] in all old rows: %s" %
  all(r["reps_ok"] and r["tail"] == list(r["tile"][:2]) for r in old_rows))
P("  desc_det rows: same structure (reps 8x + tail): %s" %
  all(r["d0"][2 + 4 * k:6 + 4 * k] == r["d0"][2:6] for r in ddet for k in range(1, 8)) and
  all(r["d0"][34:36] == r["d0"][2:4] for r in ddet))
P("  head word1 vs TILE[3] equal per row: %s" %
  [("eq" if r["w1"] == r["tile"][3] else "NEQ") for r in old_rows])
P("  word1==TILE[3] for desc_det S0/S1/S2: %s" %
  [("eq" if r["d0"][1] == r["d0"][5] else "NEQ") for r in ddet])

# desc_det S0 vs S1: same kind/session/created_at? and S0 vs S2
if len(ddet) >= 3:
    P("  desc_det S0 vs S1: claims-len %d vs %d, sec %s — DIFFERENT claims (ev pairs)" %
      (ddet[0]["d7"], ddet[1]["d7"], ddet[0]["sec"] == ddet[1]["sec"]))
    same = (ddet[0]["d7"] == ddet[2]["d7"] and ddet[0]["sec"] == ddet[2]["sec"]
            and ddet[0]["created_at"] == ddet[2]["created_at"])
    P("  desc_det S0 vs S2: same claims-len + same sec + same created_at: %s  (per-call pair)"
      % same)

# ============================================================ 3. KNOWN-VALUE SEARCH
P("")
P("=" * 78)
P("3. KNOWN-VALUE WINDOW SEARCH (4-byte windows, both dword endiannesses)")
P("=" * 78)

NEEDLES = {
    "pkg com.penti.app": b"com.penti.app",
    "moto g42": b"moto g42",
    "motorola": b"motorola",
    "os_build S2SE32.28-28-4": b"S2SE32.28-28-4",
    "cpu arm64-v8a": b"arm64-v8a",
    "android12": b"android12",
    "1080ascii": b"1080",
    "2237ascii": b"2237",
    "2400ascii": b"2400",
    "w=1080 BE": struct.pack(">I", 1080),
    "w=1080 LE": struct.pack("<I", 1080),
    "h=2237 BE": struct.pack(">I", 2237),
    "h=2237 LE": struct.pack("<I", 2237),
    "h=2400 BE": struct.pack(">I", 2400),
    "wh=(1080,2237)BE": struct.pack(">HH", 1080, 2237),
    "wh=(1080,2237)LE": struct.pack("<HH", 1080, 2237),
    "wh=(1080,2400)BE": struct.pack(">HH", 1080, 2400),
    "sdk=31 BE": struct.pack(">I", 31),
    "dpi=420 BE": struct.pack(">I", 420),
    "mapsize=53 BE": struct.pack(">I", 53),
    "SHA1#9 w0 fad0f10d": SHA1_CONST[:4],
    "SHA1#9 full": SHA1_CONST,
    "#8 bfffffff": D8_CONST[:4],
    "#8 full": D8_CONST,
}


def windows(b, n=4):
    return [b[i:i + n] for i in range(len(b) - n + 1)]


def search_blob(name, blob):
    wins_be = set(windows(blob))
    wins_le = {w[::-1] for w in wins_be}
    hits = []
    for label, nd in NEEDLES.items():
        if len(nd) < 4:
            continue
        found = False
        for w in windows(nd):
            if w in wins_be or w in wins_le:
                found = True
                break
        if nd in blob or nd[::-1] in blob:
            found = True
        if found:
            hits.append(label)
    return hits


P("-- fresh wire blobs (192 B): needles present (any 4B window, BE or LE bytes)")
for r in fresh:
    hits = search_blob("fresh%d" % r["n"], r["blob"])
    P("  fresh%d: %s" % (r["n"], hits if hits else "NONE of %d needles" % len(NEEDLES)))
P("-- probe blobs")
for nm in probe:
    if nm.endswith("_sec"):
        continue
    hits = search_blob(nm, probe[nm])
    P("  %-8s: %s" % (nm, hits if hits else "NONE"))

P("-- H raw in fresh blob: %s" % any(r["Hb"] in r["blob"] for r in fresh))
for r in fresh:
    hw = []
    for a in range(0, 29):
        w = r["Hb"][a:a + 4]
        for k in range(len(r["blob"]) - 3):
            if r["blob"][k:k + 4] == w:
                hw.append(("BE", a, k, w.hex()))
            if r["blob"][k:k + 4] == w[::-1]:
                hw.append(("LE", a, k, w.hex()))
    P("   fresh%d H-window hits: %s" % (r["n"], hw if hw else "none"))
for nm in probe:
    if nm.endswith("_sec"):
        continue
    Hb = fresh[0]["Hb"]      # probe reuses signing-1 H (h / h.clone())
    hw = []
    for a in range(0, 29):
        w = Hb[a:a + 4]
        bl = probe[nm]
        for k in range(len(bl) - 3):
            if bl[k:k + 4] == w:
                hw.append(("BE", a, k, w.hex()))
            if bl[k:k + 4] == w[::-1]:
                hw.append(("LE", a, k, w.hex()))
    if hw:
        P("   probe %-8s H-window hits: %s" % (nm, hw))
P("   (chance per blob: 176*58/2^32 = 2.4e-6)")
P("-- canon 16B head in blob: %s" %
  [r["canon"][:16] in r["blob"] for r in fresh])

P("-- old descriptors: search d0/d2/d4 words for 0x438/0x8BD/0x960 raw & byte patterns")
pats = [b"\x04\x38", b"\x38\x04", b"\x08\xbd", b"\xbd\x08", b"\x09\x60", b"\x60\x09",
        b"\x00\x00\x04\x38", b"\x38\x04\x00\x00", b"\x00\x00\x08\xbd", b"\xbd\x08\x00\x00"]
cnt = {p.hex(): 0 for p in pats}
for r in old_rows:
    for seg in (struct.pack(">36I", *r["d0"]), struct.pack(">8I", *r["d4"]),
                struct.pack(">I", r["d2"])):
        for p in pats:
            cnt[p.hex()] += seg.count(p)
P("   counts over all old rows' d0/d2/d4: %s" %
  {k: v for k, v in cnt.items() if v})

# ============================================================ 4. FRESH PAIRWISE
P("")
P("=" * 78)
P("4. FRESH PAIRWISE XOR BATTERIES (per-call seed isolation)")
P("=" * 78)


def xor(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))


def lag_struct(dx, label):
    b = dx
    n = len(b)
    res = []
    for lag in (1, 2, 4, 8, 16, 32, 64, 128):
        eq = sum(1 for i in range(n - lag) if b[i] == b[i + lag])
        res.append((lag, eq))
    exp = sum(n - lag for lag, _ in res) / 256.0
    tot = sum(eq for _, eq in res)
    P("    %s lag-equality counts %s (total %d, chance ~%.1f)" %
      (label, ["%d:%d" % (l, e) for l, e in res], tot, exp))


P("-- per fresh pair (i,j): body_i ^ body_j (176 B)")
pair_data = {}
for a in range(3):
    for b in range(a + 1, 3):
        ri, rj = fresh[a], fresh[b]
        dx = xor(ri["body"], rj["body"])
        key = (ri["n"], rj["n"])
        pair_data[key] = dx
        ndiff = sum(1 for x in dx if x)
        # header word xor
        hw = [dw_be(ri["hdr16"], 4 * k) ^ dw_be(rj["hdr16"], 4 * k) for k in range(4)]
        dsec = (rj["sec"] - ri["sec"]) if (ri["sec"] and rj["sec"]) else None
        P("  pair %s: ndiff_bytes=%d/176  dsec=%s (%s)  hdr_word_xor=%s" %
          (key, ndiff, abs(dsec) if dsec is not None else "?",
           "sec_i^sec_j=%d" % (ri["sec"] ^ rj["sec"]) if dsec is not None else "?",
           [h32(x) for x in hw]))
        dxw = dwords(dx)
        nz = sum(1 for x in dxw if x)
        P("    dword view: nonzero=%d/44  first8=%s" % (nz, [h32(x) for x in dxw[:8]]))

# dictionaries of candidate XOR values per pair
P("")
P("-- candidate-dictionary membership for each body-XOR dword")
P("   (dx == H_i[a:a+4]^H_j[a:a+4] / canon windows / header-word xor / sec deltas)")


def cand_dict(ri, rj):
    c = {}
    # H aligned windows both orders
    for a in range(0, 29):
        for order in (0, 1):
            v = xor(ri["Hb"][a:a + 4], rj["Hb"][a:a + 4])
            c[v] = "H[%d]" % a
            c[v[::-1]] = "H[%d]rev" % a
    # canon aligned+unaligned windows
    m = min(len(ri["canon"]), len(rj["canon"]))
    for a in range(0, m - 3):
        v = xor(ri["canon"][a:a + 4], rj["canon"][a:a + 4])
        c[v] = "canon[%d]" % a
    # header word xors
    for k in range(4):
        v = dw_be(ri["hdr16"], 4 * k) ^ dw_be(rj["hdr16"], 4 * k)
        c[struct.pack(">I", v)] = "hdrw%d" % k
        c[struct.pack("<I", v)] = "hdrw%dle" % k
    # seconds
    if ri["sec"] and rj["sec"]:
        for v0 in (abs(rj["sec"] - ri["sec"]), ri["sec"] ^ rj["sec"]):
            c[struct.pack(">I", v0 & 0xFFFFFFFF)] = "sec"
            c[struct.pack("<I", v0 & 0xFFFFFFFF)] = "secle"
    # ms deltas
    dv = abs(rj["ts"] - ri["ts"])
    c[struct.pack(">I", dv & 0xFFFFFFFF)] = "msdelta"
    return c


for key, dx in pair_data.items():
    ri = next(r for r in fresh if r["n"] == key[0])
    rj = next(r for r in fresh if r["n"] == key[1])
    cd = cand_dict(ri, rj)
    hits = []
    dxw = dwords(dx)
    for k, v in enumerate(dxw):
        vb = struct.pack(">I", v)
        if v == 0:
            continue
        if vb in cd:
            hits.append((k, cd[vb]))
    P("  pair %s: dword-hits %s (chance ~44*%d/2^32 = %.4f)" %
      (key, hits if hits else "NONE", len(cd), 44 * len(cd) / 2 ** 32))
    lag_struct(dx, "bodyXOR")

P("")
P("-- CONSTANT-XOR-ACROSS-SIGNINGS tests (fresh 3): is X_i ^ X_j the same for all pairs?")
def const_test(name, vals):
    # vals: list per signing of bytes
    xs = [xor(vals[0], vals[1]), xor(vals[0], vals[2]), xor(vals[1], vals[2])]
    c01 = sum(1 for x in xs[0] if x)
    same = xs[0] == xs[1] == xs[2]
    P("  %-28s pairwise-diff equal across 3 pairs: %s ; nonzero bytes %s" %
      (name, same, [c01, sum(1 for x in xs[1] if x), sum(1 for x in xs[2] if x)]))
    return same


const_test("body ^ H[:16]", [r["body"][:16] and xor(r["body"][:16], r["Hb"][:16]) for r in fresh])
const_test("body ^ H (first176 of 32B rep)", [xor(r["body"], (r["Hb"] * 6)[:176]) for r in fresh])
const_test("body ^ canon[:176]", [xor(r["body"], r["canon"][:176]) for r in fresh])
const_test("body ^ header(16B rep)", [xor(r["body"], (r["hdr16"] * 11)[:176]) for r in fresh])
const_test("body ^ H-last16 rep", [xor(r["body"], (r["Hb"][16:] * 11)[:176]) for r in fresh])
# whole-body xor with header-derived keystream: body ^ (hdr words repeated as dwords)
def hdrks(r):
    ws = dwords(r["hdr16"])
    return b"".join(struct.pack(">I", ws[k % 4]) for k in range(44))
const_test("body ^ hdr-dword-stream", [xor(r["body"], hdrks(r)) for r in fresh])

# does body ^ H-window at fixed (pos k, H offset a) stay constant across the 3?
P("")
P("-- position-scan: {body_i[k] ^ H_i[a:a+4]} singleton across the 3 signings? (k=0..43, a=0..28)")
found = []
for k in range(44):
    for j in range(8):          # H dwords (32 B = 8 dwords)
        v = set()
        for r in fresh:
            v.add(dw_be(r["body"], 4 * k) ^ dw_be(r["Hb"], 4 * j))
        if len(v) == 1:
            found.append((k, 4 * j))
P("   constant (k,a) pairs: %s%s" % (found[:10] if found else "NONE",
                                     " ... total %d" % len(found) if len(found) > 10 else ""))
P("-- position-scan: {body_i[k] ^ canon_i[a:a+4]} singleton across the 3? (a=0..1218)")
found = []
for k in range(44):
    for a in range(0, 1206):
        vals = set()
        for r in fresh:
            vals.add(dw_be(r["body"], 4 * k) ^ dw_be(r["canon"], a))
        if len(vals) == 1:
            found.append((k, a))
P("   constant (k,a) pairs: %s" % (found[:12] if found else "NONE (total %d)" % len(found)))
P("-- position-scan: {body_i[k] ^ dword(second_i)} singleton?  {^ dword(ts_i)} singleton?")
f1 = [(k) for k in range(44) if len({dw_be(r["body"], 4 * k) ^ r["sec"] for r in fresh}) == 1]
f2 = [k for k in range(44) if len({dw_be(r["body"], 4 * k) ^ (r["ts"] & 0xFFFFFFFF) for r in fresh}) == 1]
P("   sec-constant positions: %s ; ts-constant positions: %s" % (f1 or "NONE", f2 or "NONE"))

# ============================================================ 5. ORACLE PROBE
P("")
P("=" * 78)
P("5. ORACLE PROBE (controlled inputs, Hook.java oracleSuite)")
P("=" * 78)
for st in probe_stats:
    P("  " + st)

P("")
P("-- same-second pairs (identical 16-B header) -> body_i ^ body_j = PURE per-call difference")


def same_second_pairs():
    names = list(probe.keys())
    outp = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            if probe[a][:16] == probe[b][:16]:
                outp.append((a, b))
    return outp


sp = [(a, b) for a, b in same_second_pairs()]
for a, b in sp:
    dx = xor(probe[a][16:], probe[b][16:])
    ndiff = sum(1 for x in dx if x)
    P("  %s ~ %s (same header): body ndiff=%d/176  zero-dwords=%d/44" %
      (a, b, ndiff, sum(1 for x in dwords(dx) if x == 0)))
    P("    bodyXOR dwords: %s" % [h32(x) for x in dwords(dx)])
    lag_struct(dx, "same-sec bodyXOR")
if not sp:
    P("  none")

# any pair sharing >=4-byte header run?
P("-- longest common header prefix across probe pairs:")
names = list(probe.keys())
best = (0, "", "")
for i in range(len(names)):
    for j in range(i + 1, len(names)):
        a, b = probe[names[i]], probe[names[j]]
        n = 0
        while n < 16 and a[n] == b[n]:
            n += 1
        if n > best[0]:
            best = (n, names[i], names[j])
P("   longest: %d bytes between %s and %s" % best)

# Random3 continuation test on B1/B2 (same second): does body continue draws 9+?
b1, b2 = probe.get("B1_zero"), probe.get("B2_zero")
if b1 and b2 and probe_secs.get("B1_zero") == probe_secs.get("B2_zero") and probe_secs.get("B1_zero"):
    s = probe_secs["B1_zero"]
    R = hg.Random3(s)
    draws = [R.next() for _ in range(400)]
    xorw = [draws[2 * i] ^ draws[2 * i + 1] for i in range(200)]
    bw1 = dwords(b1[16:])
    bw2 = dwords(b2[16:])
    hit1 = [i for i, v in enumerate(xorw) if v in bw1]
    hit2 = [i for i, v in enumerate(xorw) if v in bw2]
    hitd = [i for i, v in enumerate(xorw) if v in dwords(xor(b1[16:], b2[16:]))]
    P("-- B1/B2 second=%d: body-dword matches against Random3(s) draws 9..400 (raw & xor-pairs):" % s)
    P("   B1 hits=%s  B2 hits=%s  B1^B2 hits=%s (chance 44*200/2^32~2e-6)" %
      (hit1[:5] or "none", hit2[:5] or "none", hitd[:5] or "none"))
    # also raw draws
    hit1r = [i for i, v in enumerate(draws) if v in bw1]
    P("   B1 raw-draw hits=%s" % (hit1r[:5] or "none"))

# A1 vs A2: different seconds, same inputs
if "A1_base" in probe and "A2_base" in probe:
    dx = xor(probe["A1_base"][16:], probe["A2_base"][16:])
    P("-- A1~A2 (same inputs, different seconds %s/%s): body ndiff=%d/176" %
      (probe.get("A1_base_sec"), probe.get("A2_base_sec"), sum(1 for x in dx if x)))
    lag_struct(dx, "A1A2 bodyXOR")
    # does sec-delta predict anything: bodyA1 ^ bodyA2 == f(secA1^secA2)?
    if probe_secs.get("A1_base") and probe_secs.get("A2_base"):
        ds = probe_secs["A1_base"] ^ probe_secs["A2_base"]
        dxA = xor(probe["A1_base"][16:], probe["A2_base"][16:])
        P("   secA1^secA2=%d secA1-A2=%d ; sec-delta dword in bodyXOR: %s ; hdrwords^sec-delta pattern: n/a" %
          (ds, probe_secs["A1_base"] - probe_secs["A2_base"],
           struct.pack(">I", ds) in windows(dxA)))

# input-sensitivity at byte level is saturated by per-call noise: quantify
P("-- input-sensitivity summary (n_diff bytes, incl. header):")
for a, b, lbl in [("A1_base", "A2_base", "same in, diff sec"),
                  ("B1_zero", "B2_zero", "same in (h=0), SAME sec"),
                  ("D1_mapX", "D2_mapX", "same mod map"),
                  ("A1_base", "B1_zero", "h=0"),
                  ("A1_base", "C1_flip", "h flip1"),
                  ("A1_base", "D1_mapX", "map changed"),
                  ("A1_base", "E1_lv30", "lvl30"),
                  ("A1_base", "F1_lv31", "lvl31")]:
    if a in probe and b in probe:
        dx = xor(probe[a], probe[b])
        P("   %-8s~%-8s %-24s ndiff=%3d/192" % (a, b, lbl, sum(1 for x in dx if x)))

# ============================================================ 6. OLD CORPUS PER-CALL
P("")
P("=" * 78)
P("6. OLD REGION CORPUS — per-call isolation, PRNG kinship, time correlation")
P("=" * 78)

# pairwise tile/W0/d2/d4 xor
P("-- pairwise: tile_i^tile_j / W0_i^W0_j / d2_i^d2_j constant across rows?")
tiles = [r["tile"] for r in old_rows] + [r["d0"][2:6] for r in ddet]
w1s = [r["w1"] for r in old_rows] + [r["d0"][1] for r in ddet]
w0s = [r["W0"] for r in old_rows] + [r["d0"][0] for r in ddet]
d2s = [r["d2"] for r in old_rows] + [r["d2"] for r in ddet]
d4s = [r["d4"] for r in old_rows] + [r["d4"] for r in ddet]
secs = [r["sec_est"] for r in old_rows] + [r["sec"] for r in ddet]
srcs = ["old%d" % i for i in range(len(old_rows))] + ["S%d" % i for i in range(len(ddet))]

tile_x = [xor(struct.pack(">4I", *tiles[i]), struct.pack(">4I", *tiles[j])).hex()
          for i in range(len(tiles)) for j in range(i + 1, len(tiles))]
P("   distinct tile^tile values: %d of %d pairs (all nonzero: %s)" %
  (len(set(tile_x)), len(tile_x), all(any(c != "0" for c in t) for t in tile_x)))
d2x = [d2s[i] ^ d2s[j] for i in range(len(d2s)) for j in range(i + 1, len(d2s))]
P("   distinct d2^d2 values: %d of %d ; zero: %d" %
  (len(set(d2x)), len(d2x), sum(1 for v in d2x if v == 0)))
w0x = [w0s[i] ^ w0s[j] for i in range(len(w0s)) for j in range(i + 1, len(w0s))]
P("   distinct W0^W0 values: %d of %d ; zero: %d" %
  (len(set(w0x)), len(w0x), sum(1 for v in w0x if v == 0)))

# d2 ^ W0 constant?  d2 ^ tile word constant?
c1 = len({d2s[i] ^ w0s[i] for i in range(len(d2s))})
c2 = len({d2s[i] ^ tiles[i][k] for i in range(len(d2s)) for k in (0, 1, 2, 3)})
P("   distinct d2^W0: %d/%d ; distinct d2^tile[k]: %d (pool %d)" % (c1, len(d2s), c2, len(d2s)))

# same-second desc_det S0 vs S2 (pure per-call region difference)
if len(ddet) >= 3 and ddet[0]["sec"] == ddet[2]["sec"]:
    a, b = ddet[0], ddet[2]
    P("-- desc_det S0~S2 (same sec=%d, same claims-len): PURE per-call region diff" % a["sec"])
    P("   W0: %s vs %s   W0^W0=%s" % (h32(a["d0"][0]), h32(b["d0"][0]), h32(a["d0"][0] ^ b["d0"][0])))
    tx = [a["d0"][2 + k] ^ b["d0"][2 + k] for k in range(4)]
    P("   w1: %s vs %s   w1^w1=%s" % (h32(a["d0"][1]), h32(b["d0"][1]), h32(a["d0"][1] ^ b["d0"][1])))
    P("   tile^tile: %s" % [h32(x) for x in tx])
    P("   d2: %s vs %s   d2^d2=%s" % (h32(a["d2"]), h32(b["d2"]), h32(a["d2"] ^ b["d2"])))
    d4x = [a["d4"][k] ^ b["d4"][k] for k in range(8)]
    P("   d4^d4: %s" % [h32(x) for x in d4x])
    # Random3 kinship between W0s: W0b = f(W0a)?
    wa, wb = a["d0"][0], b["d0"][0]
    pm = lambda x: (16807 * x) % M31
    P("   PM(wa)=%s wb? %s ; PM(wb)=%s wa? %s ; wa^sec=%s wb^sec=%s equal? %s" %
      (h32(pm(wa)), pm(wa) == wb or pm(wa) == (wb % M31), h32(pm(wb)), pm(wb) == wa,
       h32(wa ^ a["sec"]), h32(wb ^ a["sec"]), (wa ^ a["sec"]) == (wb ^ a["sec"])))
    for sh in range(1, 9):
        xs = wa
        ok = False
        for _ in range(sh):
            xs = pm(xs)
        if xs % (2 ** 32) == wb:
            ok = True
    # xorshift
    def xs32(x):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        return x
    P("   xorshift32(wa)==wb? %s ; xorshift32(wb)==wa? %s ; wb==PM_k(wa) k=1..8? %s" %
      (xs32(wa) == wb, xs32(wb) == wa,
       any((lambda v: v == wb)(__import__("functools").reduce(lambda acc, _: (16807 * acc) % M31, range(k), wa)) for k in range(1, 9))))
    # tile of S0 vs S2: equal? per-call
    P("   TILE S0==S2? %s ; d4 S0==S2? %s" %
      (a["d0"][2:6] == b["d0"][2:6], a["d4"] == b["d4"]))

# W0 vs Random3(second) draws — search draws 1..300 per row
P("-- W0/tile/d2 membership in Random3(sec) draws 1..300 (raw / xor-pairs):")
for i in range(len(w0s)):
    if secs[i] is None:
        continue
    R = hg.Random3(secs[i])
    draws = [R.next() for _ in range(300)]
    xp = [draws[2 * k] ^ draws[2 * k + 1] for k in range(150)]
    ws = dwords(make_header(secs[i]))
    hitw = [w0s[i]] and [k for k in range(4) if w0s[i] == ws[k]]
    h0 = w0s[i] in draws or w0s[i] in xp
    t0 = any(tiles[i][k] in draws or tiles[i][k] in xp for k in range(4))
    P("   %-5s sec=%d W0 in draws/xp: %s ; W0==hdrword: %s ; tile in draws/xp: %s" %
      (srcs[i], secs[i], h0, hitw or "no", t0))

# W0_{n+1} = f(W0_n): small function families over the time-sorted old rows
P("-- consecutive-W0 kinship (rows sorted by sec_est, gaps 66s/19s in fresh; old rows below)")
order = sorted(range(len(secs)), key=lambda i: (secs[i] is None, secs[i], srcs[i]))
seq = [(srcs[i], secs[i], w0s[i], d2s[i]) for i in order if secs[i] is not None]
for k in range(len(seq) - 1):
    s0, e0, w0, d20 = seq[k]
    s1, e1, w1, d21 = seq[k + 1]
    pm1 = (16807 * w0) % M31
    P("   %s(sec %d) -> %s(sec %d) dsec=%d : W0^=%s dW0=%s d2^=%s PM(W0)==W0'? %s" %
      (s0, s0 if False else e0, s1, e1, e1 - e0, h32(w0 ^ w1), h32((w1 - w0) & 0xFFFFFFFF),
       h32(d20 ^ d21), pm1 == w1 or pm1 == (w1 & 0x7FFFFFFF)))

# linear congruential solve on 3 consecutive W0 mod 2^32 and mod 2^31-1
def solve_lcg(xs, mod):
    x0, x1, x2 = xs
    d0 = (x1 - x0) % mod
    d1 = (x2 - x1) % mod
    # need inverse of d0 mod 'mod' — only try if odd
    if d0 % 2 == 0 and mod % 2 == 0:
        return None
    try:
        inv = pow(d0, -1, mod)
    except ValueError:
        return None
    a = (d1 * inv) % mod
    c = (x1 - a * x0) % mod
    return a, c


wseq = [w for _, _, w, _ in seq]
if len(wseq) >= 3:
    for mod, lbl in ((2 ** 32, "2^32"), (M31, "2^31-1")):
        r = solve_lcg(wseq[:3], mod)
        if r:
            a, c = r
            ok = all((a * wseq[k] + c) % mod == wseq[k + 1] for k in range(len(wseq) - 1))
            P("   LCG solve on first 3 W0 mod %s: a=%s c=%s ; holds on all %d: %s" %
              (lbl, h32(a), h32(c), len(wseq), ok))
        else:
            P("   LCG solve mod %s: not solvable (even delta)" % lbl)

# W0 linear in second?  W0 = a*sec + c
P("-- W0 vs sec linear fit check (exact, mod 2^32 / 2^31-1):")
secs_v = [e for _, e, _, _ in seq]
w_v = [w for _, _, w, _ in seq]
for mod, lbl in ((2 ** 32, "2^32"), (M31, "2^31-1")):
    ok_any = False
    try:
        d0 = (secs_v[1] - secs_v[0]) % mod
        inv = pow(d0, -1, mod)
        aa = ((w_v[1] - w_v[0]) % mod * inv) % mod
        cc = (w_v[0] - aa * secs_v[0]) % mod
        ok = all((aa * secs_v[k] + cc) % mod == w_v[k] for k in range(len(secs_v)))
        P("   mod %s: a=%s c=%s exact on %d rows: %s" % (lbl, h32(aa), h32(cc), len(secs_v), ok))
        ok_any = ok
    except ValueError:
        P("   mod %s: not solvable" % lbl)
    if not ok_any and lbl == "2^32":
        P("   (mod %s fallback skipped)" % lbl)

# d2 ^ second, d2 - second, d2 vs header words for old rows
P("-- d2 relation to sec / header words (per row):")
for i in range(len(d2s)):
    if secs[i] is None:
        continue
    hw = dwords(make_header(secs[i]))
    rel = [h32(d2s[i] ^ hw[k]) for k in range(4)]
    P("   %-5s sec=%d d2=%s d2^hdr=%s d2^sec=%s" %
      (srcs[i], secs[i], h32(d2s[i]), rel, h32(d2s[i] ^ secs[i])))

# tile ^ header words constant across rows?
P("-- tile[k] ^ hdrword[j] constant across old rows? (matrix of distinct counts)")
for k in range(4):
    row_counts = []
    for j in range(4):
        s = set()
        for i in range(len(tiles)):
            if secs[i] is None:
                continue
            hw = dwords(make_header(secs[i]))
            s.add(tiles[i][k] ^ hw[j])
        row_counts.append(len(s))
    P("   tile[%d]: distinct counts vs hdrword[j]: %s (n=%d rows)" %
      (k, row_counts, sum(1 for i in range(len(tiles)) if secs[i] is not None)))

# d4 vs claims (d10) constant-xor scan: d4[k] ^ d10[a:a+4] singleton across rows?
P("-- d4[k] ^ claims[a:a+4] singleton across old rows (claims differ per row)?")
hits = []
n_old = len(old_rows)
for k in range(8):
    for a in range(0, 356):
        vals = set()
        okall = True
        for r in old_rows:
            if len(r["d10"]) < a + 4:
                okall = False
                break
            vals.add(r["d4"][k] ^ dw_be(r["d10"], a))
        if okall and len(vals) == 1:
            hits.append((k, a))
P("   constant (k,a): %s" % (hits[:12] if hits else "NONE (total %d)" % len(hits)))
P("-- W0/tile/d2 ^ claims windows singleton?")
hits = []
for k in range(5):
    for a in range(0, 356):
        vals = set()
        okall = True
        for r in old_rows:
            if len(r["d10"]) < a + 4:
                okall = False
                break
            w = r["W0"] if k == 0 else r["d0"][k]
            vals.add(w ^ dw_be(r["d10"], a))
        if okall and len(vals) == 1:
            hits.append((k, a))
P("   constant (word#,a): %s" % (hits[:12] if hits else "NONE (total %d)" % len(hits)))

# tile XOR W0 / tile internal relations per row (ALL_LAWS cross-check on combined corpus)
P("-- tile internal relations on combined 13 rows:")
def rels(t):
    return (t[2] ^ t[0], t[3] ^ t[1])
seen = {}
for i in range(len(tiles)):
    x0, x1 = rels(tiles[i])
    seen.setdefault("T2^T0", set()).add(x0)
    seen.setdefault("T3^T1", set()).add(x1)
for k, v in seen.items():
    P("   %s: %d distinct of %d" % (k, len(v), len(tiles)))


# ============================================================ 6b. DEEPER LAWS
P("")
P("-- 6b. tile internal law (from all_laws.json: (T3^T1)-R||R==0, their d0[2]/d0[4])")
ok_law = 0
Rs = []
for i in range(len(tiles)):
    v = tiles[i][2] ^ tiles[i][0]
    R = v & 0xFFFF
    Rs.append(R)
    if v == (R * 0x10001):
        ok_law += 1
    else:
        P("   LAW FAIL %s: U2^U0=%s" % (srcs[i], h32(v)))
P("   U[2]^U[0] == R||R (both 16-bit halves equal): %d/%d rows; R per row: %s" %
  (ok_law, len(tiles), [h32(r)[4:] for r in Rs]))
c13 = sum(1 for i in range(len(tiles)) if (tiles[i][3] ^ tiles[i][1]) == ((tiles[i][3] ^ tiles[i][1]) & 0xFFFF) * 0x10001)
c_w0 = sum(1 for i in range(len(tiles)) if (w0s[i] ^ w1s[i]) == ((w0s[i] ^ w1s[i]) & 0xFFFF) * 0x10001)
P("   control: U[3]^U[1] R||R: %d/%d ; W0^X R||R: %d/%d (chance ~13/65536)" % (c13, len(tiles), c_w0, len(tiles)))

P("")
P("-- 6c. Random3 kinship with seeds sec/W0/X/d2 (draws 1..600, raw + adjacent-draw XOR)")
for i in range(len(tiles)):
    if secs[i] is None:
        continue
    hits = []
    for lbl, seed in (("sec", secs[i]), ("W0", w0s[i]), ("X", w1s[i]), ("d2", d2s[i])):
        try:
            R = hg.Random3(seed & 0xFFFFFFFF if seed < 2 ** 31 else seed - 2 ** 32)
        except Exception:
            continue
        draws = [R.next() for _ in range(600)]
        adj = [draws[k] ^ draws[k + 1] for k in range(599)]
        pool = set(draws) | set(adj)
        vals = {"W0": w0s[i], "X": w1s[i], "d2": d2s[i]}
        for k in range(4):
            vals["U%d" % k] = tiles[i][k]
        for nm2, v in vals.items():
            if v in pool:
                hits.append("%s:%s" % (lbl, nm2))
    if hits:
        P("   %-5s %s" % (srcs[i], hits))
P("   (no output above = no membership in Random3(sec/W0/X/d2) streams)")

P("")
P("-- 6d. duplicate check: S0/S1/S2 == old rows 7/8/9?")
for si, oi in ((0, 7), (1, 8), (2, 9)):
    a, b = ddet[si], old_rows[oi]
    eq = (a["d0"] == b["d0"] and a["d2"] == b["d2"] and a["d4"] == b["d4"]
          and a["d7"] == b["d7"] and bytes(struct.pack(">5I", *a["d9"])) == bytes(struct.pack(">5I", *b["d9"])))
    P("   S%d == old%d: %s" % (si, oi, eq))

P("")
P("-- 6e. old-corpus same-second pairs with different claims: per-call diff vectors")
for (i, j) in ((2, 3), (7, 8)):
    P("   %s~%s (sec %d): dclaims %d vs %d" % (srcs[i], srcs[j], secs[i], old_rows[i]["d7"] if i < 10 else 0, old_rows[j]["d7"] if j < 10 else 0))
    P("     W0^W0=%s X^X=%s U^U=%s d2^d2=%s" %
      (h32(w0s[i] ^ w0s[j]), h32(w1s[i] ^ w1s[j]),
       xor(struct.pack(">4I", *tiles[i]), struct.pack(">4I", *tiles[j])).hex(),
       h32(d2s[i] ^ d2s[j])))
    P("     d4^d4=%s" % [h32(d4s[i][k] ^ d4s[j][k]) for k in range(8)])
P("   NOTE S0~S2 d4[0]^d4[0]=00000480 (small); all other same-second d4 diffs are full-word")

P("")
P("-- 6f. region dwords vs property/claim string 4-byte windows (old rows)")
props = [b"motorola", b"moto g42", b"S2SE32.28-28-4", b"arm64-v8a", b"android12",
         b"com.penti.app", b"com.android.vending", b"jut9tib0eeps", b"android5.7.0",
         b"production", b"service", b"phone", b"adj9"]
hits = 0
for r in old_rows:
    segs = [struct.pack(">36I", *r["d0"]), struct.pack(">8I", *r["d4"]), struct.pack(">I", r["d2"]), r["d10"][:16]]
    for p in props:
        for w in windows(p):
            for sg in segs:
                if w in sg:
                    hits += 1
P("   4-byte window hits of 13 prop strings in d0/d2/d4/d10-head over 10 rows: %d "
  "(d10 itself is claims bytes - excluded beyond head)" % hits)

P("")
P("-- 6g. fresh nsign_in modCount per signing (from run3 log)")
log3 = open(JD + "/adj9_capture_run3.log", encoding="utf-8", errors="replace").read()
for mn in re.finditer(r"###ADJ9_BEGIN type=nsign_in.*?HashMap#modCount:int=Integer (\d+)", log3, re.S):
    pass
mcs = re.findall(r"HashMap#modCount:int=Integer (\d+)", log3)
szs = re.findall(r"map_size=(\d+)", log3)
P("   modCount values seen in nsign_in dumps: %s ; map_size events: %s" % (mcs[:6], sorted(set(szs))[:6]))

# B1~B2: which single body byte matched
if "B1_zero" in probe and "B2_zero" in probe:
    dx = xor(probe["B1_zero"][16:], probe["B2_zero"][16:])
    eqb = [k for k in range(len(dx)) if dx[k] == 0]
    P("-- B1~B2 equal body bytes (of 176): %s" % eqb)

# ============================================================ SUMMARY
P("")
P("=" * 78)
P("7. SUMMARY SNAPSHOT")
P("=" * 78)
P("(see corpus_seed.md for the write-up)")

with open(REV + "/corpus_seed.log", "w", encoding="utf-8") as f:
    f.write("\n".join(out_lines) + "\n")
print("\nsaved corpus_seed.log (%d lines)" % len(out_lines))
