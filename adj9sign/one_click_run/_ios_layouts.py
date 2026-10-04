"""Round 3: layout + seeding variants of the TYPE_3 generator (non-overlapping
with the subagents' offset/warmup/epoch scans).

Hypotheses:
  L1  word packing: BE (android law) vs LITTLE-endian
  L2  pairing: (0,1)(2,3)(4,5)(6,7) vs (0,4)(1,5)(2,6)(3,7) vs (0,3)(1,2)...
  L3  which 8 draws: first 8 vs interleaved/skipped
  S1  seeding: Schrage (bionic) vs plain 64-bit LCG state init (BSD `long`)
  S2  seeding: 32-bit truncated state init
  S3  seed itself: second, second-1, second+1 (wide offsets are subagent A's)
"""
import base64, re, sys, zipfile, struct
from datetime import datetime

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run")
import adj9_signer as S

SAZ = r"C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
z = zipfile.ZipFile(SAZ)
rows = []
for n in sorted(z.namelist()):
    if n.endswith("_c.txt"):
        d = z.read(n).decode("utf8", errors="replace")
        m = re.search(r'signature="([^"]+)"', d)
        if m:
            rows.append((int(re.search(r"(\d+)_c", n).group(1)),
                         base64.b64decode(m.group(1))[:16]))
times = {}
for n in z.namelist():
    if n.endswith("_m.xml"):
        sid = int(re.search(r"(\d+)_m", n).group(1))
        t = re.search(r'ClientBeginRequest="([^"]+)"', z.read(n).decode("utf8", "replace"))
        if t:
            times[sid] = datetime.fromisoformat(t.group(1).replace("Z", "+00:00")).timestamp()

MASK32 = 0xFFFFFFFF
MINSTD_A, MINSTD_M = 16807, (2 ** 31) - 1
MINSTD_Q, MINSTD_R = MINSTD_M // MINSTD_A, MINSTD_M % MINSTD_A


def type3_state(seed, variant):
    """31-word initial state before warmup. variant: 'schrage' | 'lcg64' | 'lcg32'."""
    s = seed & MASK32
    if s == 0:
        s = 1
    r = [0] * 31
    if variant == "schrage":
        w = s if s < 2 ** 31 else s - 2 ** 32
        r[0] = w
        prev = w
        for i in range(1, 31):
            if prev >= 0:
                hi = prev // MINSTD_Q
                lo = prev - hi * MINSTD_Q
            else:
                hi = -((-prev) // MINSTD_Q)
                lo = prev - hi * MINSTD_Q
            word = MINSTD_A * lo - MINSTD_R * hi
            if word < 0:
                word += MINSTD_M
            prev = word
            r[i] = word
    else:
        # BSD random.c literally: state[i] = 1103515245*state[i-1] + 12345
        # over C `unsigned long` (64-bit on Darwin LP64) or truncated 32-bit
        mod = (1 << 64) if variant == "lcg64" else MASK32
        prev = s
        r[0] = s
        for i in range(1, 31):
            prev = (1103515245 * prev + 12345) % mod
            r[i] = prev
    return r


def draws(seed, n=8, variant="schrage", warmup=310):
    r = [x & MASK32 for x in type3_state(seed, variant)]
    f, b = 3, 0
    out = []
    for i in range(warmup + n):
        v = (r[f] + r[b]) & MASK32
        r[f] = v
        o = v >> 1
        f = (f + 1) % 31
        b = (b + 1) % 31
        if i >= warmup:
            out.append(o)
    return out


# ---- sanity: schrage variant must equal adj9_signer.Random3 ----
import random as _r
for _ in range(50):
    sd = _r.randrange(1, 2 ** 32)
    a = draws(sd, 8, "schrage", 310)
    g = S.Random3(sd)
    b2 = [g.next() for _ in range(8)]
    assert a == b2, (sd, a, b2)
print("sanity: schrage variant == adj9_signer.Random3 on 50 random seeds  OK\n")

LAYOUTS = {
    "be-pair01": lambda d: b"".join(struct.pack(">I", (d[i] ^ d[i+1]) & MASK32) for i in range(0, 8, 2)),
    "le-pair01": lambda d: b"".join(struct.pack("<I", (d[i] ^ d[i+1]) & MASK32) for i in range(0, 8, 2)),
    "be-pair04": lambda d: b"".join(struct.pack(">I", (d[i] ^ d[i+4]) & MASK32) for i in range(4)),
    "le-pair04": lambda d: b"".join(struct.pack("<I", (d[i] ^ d[i+4]) & MASK32) for i in range(4)),
    "be-direct": lambda d: b"".join(struct.pack(">I", d[i] & MASK32) for i in range(4)),
    "le-direct": lambda d: b"".join(struct.pack("<I", d[i] & MASK32) for i in range(4)),
    "be-direct47": lambda d: b"".join(struct.pack(">I", d[i] & MASK32) for i in range(4, 8)),
    "be-quad0123": lambda d: struct.pack(">I", (d[0] ^ d[1] ^ d[2] ^ d[3]) & MASK32) + struct.pack(">I", (d[4] ^ d[5] ^ d[6] ^ d[7]) & MASK32) + b"\x00" * 8,
}
SEEDV = {"sec": 0, "sec-1": -1, "sec+1": +1}

print(f"{'seeding':<10} {'seed':<7} {'layout':<12} matches")
hits = 0
for sv in ("schrage", "lcg64", "lcg32"):
    for sname, off in SEEDV.items():
        for lname, lay in LAYOUTS.items():
            ok = sum(1 for sid, h in rows if sid in times
                     and lay(draws(int(times[sid]) + off, 8, sv, 310)) == h)
            if ok:
                hits += 1
                print(f"{sv:<10} {sname:<7} {lname:<12} {ok}/{len(rows)}  <-- HIT")
print(f"\ntotal hits: {hits}  (combos tested: 3 seedings x 3 seed offsets x 8 layouts = 72)")