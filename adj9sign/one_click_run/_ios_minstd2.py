"""Round 6b — MINSTD (Apple rand) with warmups, layouts, offsets to +/-15 min."""
import base64, re, zipfile, struct
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
        br = re.search(r'ClientBeginRequest="([^"]+)"', x)
        if br:
            times[sid] = datetime.fromisoformat(br.group(1).replace("Z", "+00:00")).timestamp()


def minstd_stream(seed, n=8, warmup=0):
    ctx = seed & 0xFFFFFFFF
    out = []
    for _ in range(n + warmup):
        x = (ctx % 0x7FFFFFFE) + 1
        hi, lo = divmod(x, 127773)
        x = 16807 * lo - 2836 * hi
        if x < 0:
            x += 0x7FFFFFFF
        ctx = x
        out.append(x)
    return out[warmup:]


def minstd_skip1(seed, n=8):
    """first call only normalizes (ctx in range afterwards): d0 = f(seed+1)."""
    return minstd_stream(seed + 1, n)


M32 = 0xFFFFFFFF
LAYOUTS = {
    "be-pair": lambda d: b"".join(struct.pack(">I", (d[i] ^ d[i + 1]) & M32) for i in range(0, 8, 2)),
    "le-pair": lambda d: b"".join(struct.pack("<I", (d[i] ^ d[i + 1]) & M32) for i in range(0, 8, 2)),
    "be-direct": lambda d: b"".join(struct.pack(">I", d[i]) for i in range(4)),
    "le-direct": lambda d: b"".join(struct.pack("<I", d[i]) for i in range(4)),
}
OFFS = list(range(-900, 61))          # -15 min .. +1 min
WARM = [0, 1, 2, 3, 4, 8, 16, 32, 64]

best = (0, None)
for warm in WARM:
    for lname, lay in LAYOUTS.items():
        for gen in (lambda s, w=warm: minstd_stream(s, 8, w), minstd_skip1):
            gname = "skip1" if gen is minstd_skip1 else f"w{warm}"
            ok = 0
            for sid, h in rows:
                if sid not in times:
                    continue
                t = int(times[sid])
                if any(lay(gen(t + o)) == h for o in OFFS):
                    ok += 1
            if ok > best[0]:
                best = (ok, (gname, lname))
            if ok:
                print(f"HIT gen={gname} layout={lname}: {ok}/{len(rows)}")
print(f"best: {best[0]}/{len(rows)}  {best[1]}")