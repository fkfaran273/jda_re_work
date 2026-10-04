"""Which PRNG makes the iOS 16-byte header?

Header shape already matches Android exactly (4 x BE 31-bit words, same-second
requests share a header). So the difference must be the RNG or the seeding.
Test candidate PRNGs x candidate seeds against every iOS header.
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


def pair(draws):
    return b"".join(struct.pack(">I", (draws[i] ^ draws[i + 1]) & 0xFFFFFFFF)
                    for i in range(0, 8, 2))


# ---- candidate PRNGs -------------------------------------------------
def bionic_random(seed):          # what make_header uses
    return [S.Random3(seed).next() for _ in range(8)]


def bionic_random_raw(seed):
    """Random3 without the 31-bit masking Random3.next may apply."""
    r = S.Random3(seed)
    return [r.next() for _ in range(8)]


def lcg_glibc(seed):              # classic 31-bit LCG, Darwin-style rand()
    s = seed & 0xFFFFFFFF
    out = []
    for _ in range(8):
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((s >> 16) & 0x7FFFFFFF)
    return out


def lcg_knuth(seed):
    s = seed & 0xFFFFFFFF
    out = []
    for _ in range(8):
        s = (s * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(s)
    return out


def lcg_msvc(seed):
    s = seed & 0xFFFFFFFF
    out = []
    for _ in range(8):
        s = (s * 214013 + 2531011) & 0xFFFFFFFF
        out.append((s >> 16) & 0x7FFFFFFF)
    return out


PRNGS = {
    "bionic(Random3)": bionic_random,
    "glibc-lcg>>16": lcg_glibc,
    "glibc-lcg-full": lcg_knuth,
    "msvc-lcg>>16": lcg_msvc,
}
SEEDS = {
    "sec": lambda t: int(t),
    "sec-1": lambda t: int(t) - 1,
    "sec+1": lambda t: int(t) + 1,
    "ms/1000": lambda t: int(t * 1000),
    "ms": lambda t: int(t * 1000) & 0x7FFFFFFF,
}

print(f"{'prng':<18} {'seed':<8} {'matches':>8}")
for pname, prng in PRNGS.items():
    for sname, sf in SEEDS.items():
        ok = 0
        for sid, hdr in rows:
            if sid not in times:
                continue
            try:
                if pair(prng(sf(times[sid]))) == hdr:
                    ok += 1
            except Exception:
                pass
        if ok:
            print(f"{pname:<18} {sname:<8} {ok:>5}/{len(rows)}")
print("(only non-zero matchers are printed)")

# ---- does the header match at all under ANY seed in a wide window? ----
print("\nwide-window scan with the Android PRNG (+/- 1 day):")
hit = 0
for sid, hdr in rows[:6]:
    if sid not in times:
        continue
    ts = int(times[sid])
    found = None
    for d in range(-86400, 86400, 1):
        if pair(bionic_random(ts + d)) == hdr:
            found = d
            break
    print(f"  sid {sid}: {'offset ' + str(found) if found is not None else 'no seed in +/-24h'}")
    hit += found is not None
print(f"  -> {hit} of 6 invertible even over a full day")