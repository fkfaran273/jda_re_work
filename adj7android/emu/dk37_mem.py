# DK37 dynamic hunt: after a mint, scan emu heap+stack for a 64-B block whose
# first 32 bytes XOR 0x36/0x5c patterns verify as the HMAC key against the
# minted blob's own tag.  Also record the movk-immediate candidates statically.
import hmac, hashlib, sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP, STACK, STACK_SZ
from unicorn import UcError

params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
e = Emu()
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
body, tag = out[16:272], out[272:304]
print("minted tag", tag.hex())

uc = e.uc
regions = []
try:
    regions.append(("heap", HEAP, bytes(uc.mem_read(HEAP, e.brk - HEAP))))
except UcError:
    pass
try:
    regions.append(("stack", STACK, bytes(uc.mem_read(STACK, STACK_SZ))))
except UcError:
    pass
try:
    regions.append(("libdata", 0x400000 + 0x113d80,
                    bytes(uc.mem_read(0x400000 + 0x113d80, 0x4000))))
except UcError:
    pass

found = False
for rname, base, buf in regions:
    for off in range(0, len(buf) - 32):
        w = buf[off:off + 32]
        for mask, mname in ((0x36, "ipad"), (0x5C, "opad")):
            k = bytes(b ^ mask for b in w)
            if hmac.new(k, body, hashlib.sha256).digest() == tag:
                print("DK37 FOUND via %s in %s @%#x: %s" %
                      (mname, rname, base + off, k.hex().upper()))
                found = True
if not found:
    print("no ipad/opad-style hit")

# movk register constants from nSign entry, all orderings of 4, both endians,
# plus XOR-masked variants
consts = [0xed1f071ea6fe1ede, 0x3ace195dd3930386, 0x29ff0ff794febe2e,
          0xfeee7e65b66b0f05, 0xd108a90e38b691a0, 0xbfa497f20132bece,
          0xa952fa75448bcb40, 0x87b1ff2df68e38ae, 0xc0f51250277e5cfd]
from itertools import permutations
cands = set()
for perm in permutations(range(9), 4):
    for endi in ("little", "big"):
        b = b"".join(consts[i].to_bytes(8, endi) for i in perm)
        cands.add(b)
        for m in (0x75, 0x16, 0xCC, 0x55, 0xBB):
            cands.add(bytes(x ^ m for x in b))
for c in cands:
    if hmac.new(c, body, hashlib.sha256).digest() == tag:
        print("DK37 = movk combo:", c.hex().upper())
        found = True
if not found:
    print("no movk combo hit either")
