"""Round 5 — close the offset gap.

Subagent timing data: signing happens up to 4s BEFORE ClientBeginRequest.
My earlier non-bionic PRNG tests only used offsets -1/0/+1 -> lrand48, glibc,
MSVC etc were NEVER tested at -2..-4. This sweep covers offsets -10..+10 for
every candidate libc rand implementation on Darwin, using the exact signing
window per request.
"""
import base64, re, sys, zipfile, struct
from datetime import datetime

SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
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
        x = z.read(n).decode("utf8", "replace")
        cc = re.search(r'ClientConnected="([^"]+)"', x)
        br = re.search(r'ClientBeginRequest="([^"]+)"', x)
        if cc and br:
            times[sid] = (datetime.fromisoformat(cc.group(1).replace("Z", "+00:00")).timestamp(),
                          datetime.fromisoformat(br.group(1).replace("Z", "+00:00")).timestamp())

M32, M48 = 0xFFFFFFFF, (1 << 48) - 1


def lrand48(seed):
    X = (((seed & 0xFFFFFFFF) << 16) | 0x330E) & M48
    out = []
    for _ in range(8):
        X = (0x5DEECE66D * X + 0xB) & M48
        out.append(X >> 17)
    return out


def mrand48_31(seed):
    X = (((seed & 0xFFFFFFFF) << 16) | 0x330E) & M48
    out = []
    for _ in range(8):
        X = (0x5DEECE66D * X + 0xB) & M48
        out.append((X >> 16) & 0x7FFFFFFF)
    return out


def glibc16(seed):
    s = seed & M32
    out = []
    for _ in range(8):
        s = (s * 1103515245 + 12345) & M32
        out.append((s >> 16) & 0x7FFFFFFF)
    return out


def msvc16(seed):
    s = seed & M32
    out = []
    for _ in range(8):
        s = (s * 214013 + 2531011) & M32
        out.append((s >> 16) & 0x7FFFFFFF)
    return out


def java48(seed):
    s = ((seed ^ 0x5DEECE66D) & ((1 << 48) - 1))
    out = []
    for _ in range(8):
        s = (s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        out.append(s >> 17)
    return out


def pair(d):
    return b"".join(struct.pack(">I", (d[i] ^ d[i + 1]) & M32) for i in range(0, 8, 2))


GENS = {"lrand48": lrand48, "mrand48&31": mrand48_31, "glibc>>16": glibc16,
        "msvc>>16": msvc16, "java48": java48}

print(f"{'gen':<12} {'offset':>6}  matches")
any_hit = False
for gname, gen in GENS.items():
    for off in range(-10, 11):
        ok = 0
        for sid, h in rows:
            if sid not in times:
                continue
            lo, hi = times[sid]
            # try every second in the signing window, shifted by off
            for sec in range(int(lo) + off, int(hi) + 1 + off):
                if pair(gen(sec)) == h:
                    ok += 1
                    break
        if ok:
            any_hit = True
            print(f"{gname:<12} {off:>+6}  {ok}/{len(rows)}  <-- HIT")
if not any_hit:
    print("  (no hits at any offset -10..+10 for any non-bionic generator)")