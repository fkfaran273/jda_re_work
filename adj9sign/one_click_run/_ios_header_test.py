"""Does the iOS capture obey the SAME 16-byte header law as Android?

Header law: make_header(second) = bionic srand(second) -> 8 draws -> 4 BE int32 XOR pairs.
Invert it by replaying the forward law over a window of seconds around the capture
clock and matching the observed 16 bytes.
"""
import base64, re, sys, zipfile
from datetime import datetime

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run")
import adj9_signer as S

SAZ = r"C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"

z = zipfile.ZipFile(SAZ)
sigs = []  # (sid, host, path, blob16, blob)
for n in sorted(z.namelist()):
    if not n.endswith("_c.txt"):
        continue
    d = z.read(n).decode("utf8", errors="replace")
    m = re.search(r'signature="([^"]+)"', d)
    if not m:
        continue
    sid = int(re.search(r"(\d+)_c\.txt", n).group(1))
    host = re.search(r"Host: (\S+)", d)
    path = re.search(r"^(?:POST|GET) (\S+)", d)
    raw = base64.b64decode(m.group(1))
    sigs.append((sid, host.group(1) if host else "?",
                 path.group(1).split("?")[0] if path else "?", raw))

# capture wall clock per session, in unix seconds
times = {}
for n in z.namelist():
    if not n.endswith("_m.xml"):
        continue
    sid = int(re.search(r"(\d+)_m\.xml", n).group(1))
    t = re.search(r'ClientBeginRequest="([^"]+)"', z.read(n).decode("utf8", "replace"))
    if t:
        times[sid] = datetime.fromisoformat(t.group(1).replace("Z", "+00:00"))

# precompute the forward law once per second over a wide window
LO, HI = -30, 90
cache = {}


def hdr(sec):
    if sec not in cache:
        cache[sec] = bytes(S.make_header(sec))
    return cache[sec]


print(f"{'sid':>5} {'host':<18} {'path':<14} {'recovered':>10}  {'delta_s':>8}  match")
ok = 0
total = 0
for sid, host, path, raw in sigs:
    if sid not in times:
        continue
    ts = int(times[sid].timestamp())
    target = raw[:16]
    hit = None
    for d in range(LO, HI):
        sec = ts + d
        if hdr(sec) == target:
            hit = (sec, d)
            break
    total += 1
    if hit:
        ok += 1
        print(f"{sid:>5} {host:<18} {path:<14} {hit[0]:>10}  {hit[1]:>+8}  OK")
    else:
        print(f"{sid:>5} {host:<18} {path:<14} {'-':>10}  {'-':>8}  NO MATCH")

print()
print(f"HEADER LAW: {ok}/{total} iOS signatures inverted to the capture second")
print(f"unique recovered deltas: {sorted({d for _, _, _, r in sigs if False}) or 'see above'}")