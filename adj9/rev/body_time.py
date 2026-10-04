# body_time.py — what makes the 176B body vary between two nSign calls that share
# a seed second?  Candidates: gettimeofday usec / clock_gettime ns / getpid /
# getauxval(AT_RANDOM) — those are the only per-call entropy sources in the import
# table (no open/getrandom/arc4random, no /dev/urandom string in the .so).
#
# Tests:
#  1. is the body a PERMUTATION of a fixed byte pool?  (sorted-multiset / sum / xor)
#  2. does any byte field encode t0/t1 (ms) or usec, BE or LE, 32/64-bit?
#  3. per-byte and per-BE-word32 correlation with the ms timestamp
#  4. constant positions across all rapid rows (structural markers)
import re, collections, struct, itertools, statistics

PATH = "C:/Users/Apps/Downloads/com.penti.app/adj9/cap/oracle_run7.log"

def parse_events(path):
    ev, cur = [], None
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\S+) ts=(\d+)", ln)
        if m:
            cur = {"type": m.group(1), "ts": int(m.group(3)), "body": []}
            ev.append(cur); continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"): cur = None; continue
            cur["body"].append(ln.rstrip("\n"))
    return ev

rows = {}
for e in parse_events(PATH):
    if not (e["type"].startswith("rapid_batch") or e["type"] == "rapid_fire"):
        continue
    T = "\n".join(e["body"])
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=(\d+) sec=(\d+) len=192\n([0-9a-f]+)", T):
        rows[int(m.group(1))] = (int(m.group(2)), int(m.group(3)), bytes.fromhex(m.group(6)))

idx = sorted(rows)
print("rapid rows:", len(idx))
R = [(i, rows[i][0], rows[i][1], rows[i][2]) for i in idx]
t0s = [r[1] for r in R]
bodies = [r[3][16:] for r in R]
heads = [r[3][:16] for r in R]

# ---------- 1. permutation-of-fixed-pool test ----------
print("\n=== 1. is the body a permutation of a fixed byte pool? ===")
sigs = {}
for i, (n, t0, t1, b) in enumerate(R):
    sigs.setdefault(bytes(sorted(b[16:])), []).append(n)
print("distinct sorted-body multisets:", len(sigs), "(1 => pool permutation, %d => not)" % len(R))
print("sum-of-bytes:  ", [sum(b) for b in bodies])
print("xor-of-bytes:  ", [bytes([b[0]]) + bytes(itertools.accumulate(b[1:], lambda a, c: a ^ c))[-1:] and b'' or b'' for b in bodies] and
      [hex(__import__('functools').reduce(lambda a, c: a ^ c, b, 0)) for b in bodies])
print("mean byte:     ", ["%.1f" % (sum(b) / len(b)) for b in bodies])
# byte histogram distance between first two
h0 = collections.Counter(bodies[0]); h1 = collections.Counter(bodies[1])
common = sum(min(h0[k], h1[k]) for k in set(h0) | set(h1))
print("histogram overlap rows %d vs %d: %d/176 (176 => same multiset)" % (R[0][0], R[1][0], common))

# ---------- 2. raw time encodings ----------
print("\n=== 2. any field equal to t0 / t1 / sec / usec? ===")
def u32be(b, o): return struct.unpack_from(">I", b, o)[0]
def u32le(b, o): return struct.unpack_from("<I", b, o)[0]
def u64be(b, o): return struct.unpack_from(">Q", b, o)[0]
def u64le(b, o): return struct.unpack_from("<Q", b, o)[0]

for name, fn, width in (("u32be", u32be, 4), ("u32le", u32le, 4), ("u64be", u64be, 8), ("u64le", u64le, 8)):
    hits = 0
    for (n, t0, t1, b) in R:
        for cand, lbl in ((t0, "t0"), (t1, "t1"), (t0 // 1000, "t0s"), (t1 // 1000, "t1s"),
                          (t0 % 1000000, "t0us"), (t0 // 1000, "sec")):
            for o in range(0, 192 - width + 1):
                if fn(b, o) == cand & ((1 << (width * 8)) - 1):
                    hits += 1
    print("  %s: %d exact matches" % (name, hits))

# ---------- 3. correlation with ms timestamp ----------
print("\n=== 3. per-position correlation with t0 (ms), n=%d ===" % len(R))
def pear(xs, ys):
    n = len(xs); mx = sum(xs) / n; my = sum(ys) / n
    sx = (sum((x - mx) ** 2 for x in xs)) ** .5
    sy = (sum((y - my) ** 2 for y in ys)) ** .5
    if sx == 0 or sy == 0: return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy)

corr = []
for p in range(192):
    ys = [r[3][p] for r in R]
    corr.append((abs(pear(t0s, ys)), p, pear(t0s, ys)))
corr.sort(reverse=True)
print("  strongest |r| byte positions:", [(p, round(c, 3)) for _, p, c in corr[:8]])
print("  |r| threshold: 0.5 =>", sum(1 for a, _, _ in corr if a > 0.5), "positions")
wcorr = []
for p in range(0, 189, 1):
    ys = [struct.unpack_from(">I", r[3], p)[0] for r in R]
    wcorr.append((abs(pear(t0s, ys)), p))
wcorr.sort(reverse=True)
print("  strongest |r| BE-word32 offsets:", [(p, round(c, 3)) for c, p in wcorr[:8]])

# ---------- 4. constant positions ----------
print("\n=== 4. positions constant across all %d rows ===" % len(R))
const = [p for p in range(192) if len({r[3][p] for r in R}) == 1]
print("  constant:", const)
lowvar = [(p, len({r[3][p] for r in R})) for p in range(192)]
lowvar.sort(key=lambda x: x[1])
print("  lowest-cardinality positions (pos,#distinct):", lowvar[:10])
print("\n  header cardinalities 0..15:", [len({r[3][p] for r in R}) for p in range(16)])
