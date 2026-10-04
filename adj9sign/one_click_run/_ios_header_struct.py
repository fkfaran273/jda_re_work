"""Structural analysis of the iOS 16-byte header vs the Android law."""
import base64, re, sys, zipfile, struct

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run")
import adj9_signer as S

SAZ = r"C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
z = zipfile.ZipFile(SAZ)

hdrs = []
for n in sorted(z.namelist()):
    if not n.endswith("_c.txt"):
        continue
    d = z.read(n).decode("utf8", errors="replace")
    m = re.search(r'signature="([^"]+)"', d)
    if m:
        hdrs.append(base64.b64decode(m.group(1))[:16])

print("=== iOS header: 4 BE words, check 31-bit (draw) law ===")
all31 = 0
for h in hdrs:
    w = struct.unpack(">4I", h)
    ok = all(x < 0x80000000 for x in w)
    all31 += ok
    print("  ", h.hex(), [f"0x{x:08x}" for x in w], "31bit" if ok else "** not 31bit **")
print(f"\nall four words < 2^31 : {all31}/{len(hdrs)}")

print("\n=== duplicate headers (same-second signature) ===")
from collections import Counter
c = Counter(h.hex() for h in hdrs)
for k, v in c.most_common(5):
    print(f"  {k}  x{v}")
print(f"  unique headers: {len(c)} / {len(hdrs)}")

print("\n=== is the body MSB law also the same? (uniform expected) ===")
bodies = []
for n in sorted(z.namelist()):
    if n.endswith("_c.txt"):
        d = z.read(n).decode("utf8", errors="replace")
        m = re.search(r'signature="([^"]+)"', d)
        if m:
            bodies.append(base64.b64decode(m.group(1))[16:])
allb = b"".join(bodies)
msb = sum(1 for x in allb if x >= 0x80) / len(allb)
print(f"  body bytes: {len(allb)}  fraction with MSB set: {msb:.3f}  (uniform ~0.5)")
print(f"  body mean: {sum(allb)/len(allb):.1f}  (uniform ~127.5)")

print("\n=== bionic-law sanity: does make_header reproduce the ANDROID vectors? ===")
for sec in (1790341508,):
    print(f"  make_header({sec}) = {bytes(S.make_header(sec)).hex()}")