"""Round 4: Darwin/BSD 'old-style' seeding of random().

Bionic (Android) fills all 31 state words via MINSTD Schrage -- that is
adj9_signer.Random3, byte-exact on Android. Classic BSD random.c instead:
  state[0] = seed
  state[i] = 1103515245*state[i-1] + 12345   (int32) for i = 1..9
  state[10..30] = the STATIC randtbl constants (never overwritten)
  fptr = &state[3], rptr = &state[0], discard 310, output = (v>>1)&0x7fffffff
Also try: seed fill of 10 words via Schrage instead of the LCG,
and every second inside the signing window [ClientConnected, ClientBeginRequest].
"""
import base64, re, sys, zipfile, struct
from datetime import datetime

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
        x = z.read(n).decode("utf8", "replace")
        cc = re.search(r'ClientConnected="([^"]+)"', x)
        br = re.search(r'ClientBeginRequest="([^"]+)"', x)
        if cc and br:
            times[sid] = (datetime.fromisoformat(cc.group(1).replace("Z", "+00:00")).timestamp(),
                          datetime.fromisoformat(br.group(1).replace("Z", "+00:00")).timestamp())

RANDTBL = [3,
           -1726662223, 379960547, 1735697613, 1040273694, 1313901226,
           1627687941, -179304937, -2073333483, 1780058412, -1989503057,
           -615974602, 344556628, 939512070, -1249116260, 1507946756,
           -812545463, 154635395, 1388815473, -1926676823, 525320961,
           -1009028674, 968117788, -123449607, 1284210825, 435012392,
           -2017506339, -911064859, -370259173, 1132637927, 1398500161,
           -205601318]  # [0] is the TYPE marker; state words are [1:32]

M32 = 0xFFFFFFFF


def s32(x):
    x &= M32
    return x - (1 << 32) if x >= (1 << 31) else x


def darwin_state(seed, fill):
    st = RANDTBL[1:32][:]  # 31 signed words
    st[0] = s32(seed)
    if fill == "lcg10":
        for i in range(1, 10):
            st[i] = s32(1103515245 * st[i - 1] + 12345)
    elif fill == "lcg31":
        for i in range(1, 31):
            st[i] = s32(1103515245 * st[i - 1] + 12345)
    elif fill == "lcg10_seedonly":
        for i in range(1, 10):
            st[i] = s32(1103515245 * st[i - 1] + 12345)
    return st


def darwin_draws(seed, n=8, warmup=310, fill="lcg10"):
    st = darwin_state(seed, fill)
    f, b = 3, 0
    out = []
    for i in range(warmup + n):
        v = s32(st[f] + st[b])          # *fptr += *rptr
        st[f] = v
        out_i = (v & M32) >> 1          # (uint32)v >> 1
        f = (f + 1) % 31
        b = (b + 1) % 31
        if i >= warmup:
            out.append(out_i)
    return out


def pair(d):
    return b"".join(struct.pack(">I", (d[i] ^ d[i + 1]) & M32) for i in range(0, 8, 2))


print("=== Darwin random() with static-table seeding, signing windows ===")
for fill in ("lcg10", "lcg31"):
    for warm in (310, 0):
        ok = 0
        for sid, h in rows:
            if sid not in times:
                continue
            lo, hi = times[sid]
            for sec in range(int(lo), int(hi) + 1):
                if pair(darwin_draws(sec, 8, warm, fill)) == h:
                    ok += 1
                    break
        print(f"  fill={fill:<6} warmup={warm:<3} window-match: {ok}/{len(rows)}")

print("\n=== same, seed = second across +/-8s (paranoia margin) ===")
for fill in ("lcg10",):
    for warm in (310,):
        ok = 0
        for sid, h in rows:
            if sid not in times:
                continue
            lo, hi = times[sid]
            for sec in range(int(lo) - 8, int(hi) + 9):
                if pair(darwin_draws(sec, 8, warm, fill)) == h:
                    ok += 1
                    break
        print(f"  fill={fill} warmup={warm}: {ok}/{len(rows)}")