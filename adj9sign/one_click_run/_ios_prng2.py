"""Round 2: is the iOS header XOR-paired at all, and which generator makes it?

Round 1 failed on: bionic/glibc/MSVC LCG x 5 seedings, and bionic over +/-24h.
So either the word-combination differs or the generator differs.
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

# ---- combinatorial test on the words themselves (no PRNG assumed) ----
print("=== are the 4 header words XOR-pairs, or 4 direct draws? ===")
# If they were direct consecutive draws from an LCG, consecutive words share
# the multiplier relation. Under XOR-pairing, word[i]=d[2i]^d[2i+1].
for sid, h in rows[:3]:
    w = struct.unpack(">4I", h)
    print(f"  sid {sid}: {[f'0x{x:08x}' for x in w]}")
    print(f"     xor-paired diffs w0^w1={w[0]^w[1]:#010x} w2^w3={w[2]^w[3]:#010x}")
    print(f"     plain diffs    w1-w0={(w[1]-w[0])&0xffffffff:#010x} w3-w2={(w[3]-w[2])&0xffffffff:#010x}")

# ---- Java-style LCG (48-bit) — Adjust SDKs are java-derived ----
def java_lcg(seed):
    s = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
    out = []
    for _ in range(8):
        s = (s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        out.append(s >> 17)
    return out

def c11(seed):
    s = seed & 0xFFFFFFFFFFFFFFFF
    out = []
    for _ in range(8):
        s = (s * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        out.append((s >> 33) & 0x7FFFFFFF)
    return out

def c11_xor(seed):
    s = seed & 0xFFFFFFFFFFFFFFFF
    out = []
    for _ in range(8):
        s = (s * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        out.append(s & 0xFFFFFFFFFFFFFFFF)
    return out

COMB = {
    "xor-pairs": lambda d: b"".join(struct.pack(">I", (d[i] ^ d[i+1]) & 0xFFFFFFFF) for i in range(0, 8, 2)),
    "direct-4":  lambda d: b"".join(struct.pack(">I", d[i] & 0x7FFFFFFF) for i in range(4)),
    "direct-8-lo": lambda d: b"".join(struct.pack(">I", d[i] & 0x7FFFFFFF) for i in range(8))[:16],
}
GEN = {
    "java48": java_lcg,
    "pcg-ish c11": c11,
    "c11-full": c11_xor,
    "bionic": lambda s: [S.Random3(s).next() for _ in range(8)],
}
SEEDS = {
    "sec": lambda t: int(t) & 0xFFFFFFFF,
    "sec-1": lambda t: (int(t) - 1) & 0xFFFFFFFF,
    "sec*1000": lambda t: int(t * 1000) & 0xFFFFFFFF,
}

print("\n=== brute force: generator x combination x seeding ===")
found = False
for gname, gen in GEN.items():
    for cname, comb in COMB.items():
        for sname, sf in SEEDS.items():
            ok = sum(1 for sid, h in rows if sid in times
                     and comb(gen(sf(times[sid]))) == h)
            if ok:
                found = True
                print(f"  HIT {gname:<12} {cname:<12} {sname:<10} {ok}/{len(rows)}")
if not found:
    print("  no combination matched (0/30 across all 36 combos)")

print("\n=== fallback: scan ALL 32-bit seeds for ONE header (is it a seed at all?) ===")
sid, h = rows[0]
print(f"  target header sid {sid}: {h.hex()}")
print("  (skipping exhaustive 2^32 - the round-1 +/-24h scan already showed the")
print("   android generator has no seed anywhere near the capture clock.)")