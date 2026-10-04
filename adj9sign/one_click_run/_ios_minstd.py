"""Round 6 — Apple rand() = FreeBSD do_rand = MINSTD Lehmer generator.

From apple-oss-distributions/Libc/stdlib/FreeBSD/rand.c:
  do_rand(ctx):
      x = (ctx % 0x7ffffffe) + 1        # normalize to [1, 0x7ffffffe]
      hi = x / 127773 ; lo = x % 127773
      x = 16807*lo - 2836*hi            # Schrage, a=16807 m=2^31-1
      if x < 0: x += 0x7fffffff
      ctx = x ; return x
  srand(seed): ctx = seed               # 0 -> 123459876

So the hypothesized iOS header law:
  seed = time(NULL); d[0..7] = 8 successive do_rand outputs;
  word_i = d[2i]^d[2i+1]; header = BE32 x4.
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


def apple_rand_stream(seed, n=8):
    ctx = seed & 0xFFFFFFFF
    out = []
    for _ in range(n):
        x = (ctx % 0x7FFFFFFE) + 1
        hi, lo = divmod(x, 127773)
        x = 16807 * lo - 2836 * hi
        if x < 0:
            x += 0x7FFFFFFF
        ctx = x
        out.append(x)
    return out


def pair(d):
    return b"".join(struct.pack(">I", (d[i] ^ d[i + 1]) & 0xFFFFFFFF)
                    for i in range(0, 8, 2))


print("=== MINSTD (Apple rand) across each request's signing window ===")
ok = 0
detail = []
for sid, h in rows:
    if sid not in times:
        continue
    lo, hi = times[sid]
    hit = None
    for sec in range(int(lo), int(hi) + 1):
        if pair(apple_rand_stream(sec)) == h:
            hit = sec
            break
    if hit is not None:
        ok += 1
        detail.append((sid, hit))
print(f"  window match: {ok}/{len(rows)}")

if ok < len(rows):
    print("\n=== widen to +/-30 s around ClientBeginRequest ===")
    ok2 = 0
    for sid, h in rows:
        if sid not in times:
            continue
        t = int(times[sid][1])
        if any(pair(apple_rand_stream(t + o)) == h for o in range(-30, 31)):
            ok2 += 1
    print(f"  wide match: {ok2}/{len(rows)}")

if detail:
    print("\n  matched seconds (sid -> signing second):")
    for sid, sec in detail:
        print(f"    {sid} -> {sec}")
    print("\n  *** iOS HEADER LAW = MINSTD srand(time(NULL)) — CRACKED ***")