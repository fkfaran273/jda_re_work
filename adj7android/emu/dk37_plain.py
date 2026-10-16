# Runtime-plain DK37 hunt: after a mint, test every 32/64-B window of the
# emulated lib image + heap + stack as HMAC key / sha256 prefix-suffix vs tag.
import hmac, hashlib, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP, STACK, STACK_SZ
from unicorn import UcError

params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
e = Emu()
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
body, tag = out[16:272], out[272:304]
print("minted tag", tag.hex())

uc = e.uc
regions = []
for nm, lo, ln in (("libdata", BASE + 0x11bd80, 0x4000),
                   ("bss", BASE + 0x11f0e0, 0xaa8),
                   ("heap", HEAP, e.brk - HEAP),
                   ("stack", STACK, STACK_SZ)):
    try:
        regions.append((nm, lo, bytes(uc.mem_read(lo, ln))))
    except UcError:
        print("skip", nm)

found = []
for nm, base, buf in regions:
    step = 1 if nm in ("libdata", "bss") else 4
    for off in range(0, max(len(buf) - 64, 0), step):
        w32 = buf[off:off + 32]
        if hmac.new(w32, body, hashlib.sha256).digest() == tag:
            found.append(("hmac32 " + nm, base + off, w32.hex()))
        w64 = buf[off:off + 64]
        if hmac.new(w64, body, hashlib.sha256).digest() == tag:
            found.append(("hmac64 " + nm, base + off, w64.hex()))
        if hashlib.sha256(w32 + body).digest() == tag:
            found.append(("sha_pre32 " + nm, base + off, w32.hex()))
        if hashlib.sha256(body + w32).digest() == tag:
            found.append(("sha_suf32 " + nm, base + off, w32.hex()))
for what, addr, k in found:
    print("FOUND %s @%#x %s" % (what, addr, k.upper()))
if not found:
    print("no runtime-plain hit")
