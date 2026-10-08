"""soverify_probe1.py -- R1 probe run on the REFERENCE libsigner.so (AAR).

One emu signing with a marker map that carries ALL 98 adj7_pure.CLAIM_POOL
keys (distinct marker values), non-pool canaries, and empty-string pool
values.  Logs every rand()/srand() call.  Afterwards:
  - decode the native's claims buffer from the heap (pool ORDER + pin
    position + empty-value handling + secret_id/seq),
  - recover the minted blob's nonce12 and correlate with the rand draws
    (nonce derivation law),
  - mint the same map/nonce/second with adj7_pure and compare blobs.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))      # adj7_pure
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7_work")  # emu

import adj7_pure as ap  # noqa: E402
import adj7s3_emu as base  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X0  # noqa: E402

SEC = 1791365803

POOL = list(ap.CLAIM_POOL)
print("pool keys:", len(POOL))

# marker values: K<idx> for pool keys; specials readable
SPECIAL = {"seq": "SQV", "secret_id": "SIDV", "package_name": "PKGV",
           "session_count": "SCV", "app_token": "APPV", "created_at": "CRV",
           "partner_params": "PPV"}
EMPTY = {"params", "payload", "details", "sharing", "measurement"}
m = {}
for i, k in enumerate(POOL):
    if k in SPECIAL:
        m[k] = SPECIAL[k]
    elif k in EMPTY:
        m[k] = ""
    else:
        m[k] = "K%02d" % i
# non-pool canaries
m["zzz_not_in_pool"] = "ZNP"
m["endpoint"] = "EPV"
m["language"] = "LANG"
m["attribution_deeplink"] = "ADLINK"
m["activity_kind"] = "session"
m["client_sdk"] = "android5.6.0"


class ProbeEmu(base.Emu):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.rand_log = []
        self.srand_log = []
        self.out_buf = None

    def plt_dispatch(self, uc, name):
        if name == "rand":
            self.rand_log.append(len(self.rand_log))
        elif name == "srand":
            self.srand_log.append(uc.reg_read(UC_ARM64_REG_X0))
        return super().plt_dispatch(uc, name)

    def jni_call(self, uc, idx, x):
        if idx == 208 and self.out_buf is None and x[3] == 304:
            self.out_buf = x[4]
        return super().jni_call(uc, idx, x)


import contextlib
import io

emu = ProbeEmu(verbose=False)
emu.fixed_time = SEC
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    out = emu.run(payload=bytes(32), mapobj=m)
    if out is None and emu.out_buf is not None:
        out = bytes(emu.uc.mem_read(emu.out_buf, 304))
print("blob:", out.hex().upper()[:80], "..." if out else "NONE")
print("srand calls:", emu.srand_log)
print("rand draws:", len(emu.rand_log))

# ---- nonce recovery from the blob -------------------------------------------
blob = out
body = None
INV_SBOX = [0] * 256
for _v, _s in enumerate(ap.AES_SBOX):
    INV_SBOX[_s] = _v
_INV_MCM = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def _isr(b):
    o = bytearray(16)
    for c in range(4):
        for r in range(4):
            o[4 * ((r + c) % 4) + c] = b[4 * r + c]
    return bytes(o)


def _mcm(b, mat):
    o = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= ap._gmul(col[j], mat[i][j])
            o[4 * q + i] = v
    return bytes(o)


def unspn(C, keys):
    x = bytes(a ^ b for a, b in zip(C, keys[14]))
    x = _isr(x)
    for r in range(13, 0, -1):
        x = bytes(INV_SBOX[v] for v in x)
        x = bytes(a ^ b for a, b in zip(x, keys[r]))
        x = _mcm(x, _INV_MCM)
        x = _isr(x)
    x = bytes(INV_SBOX[v] for v in x)
    return bytes(a ^ b for a, b in zip(x, keys[0]))


rec = b""
prev = blob[:16]
for k in range(16, 272, 16):
    c = blob[k:k + 16]
    rec += bytes(a ^ b for a, b in zip(unspn(c, ap._RK), prev))
    prev = c
s = rec.decode("latin1", "replace")
print("record:", s[:120], "...")
a = int(re.search(r'"a":\s*(\d+)', s).group(1))
d8 = re.search(r'"d":\s*"([0-9A-Fa-f]{8})"', s).group(1)
nonce12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
print("nonce12:", nonce12.hex(), "a-width:", len(str(a)))

# ---- heap claims buffer ------------------------------------------------------
heap = bytes(emu.uc.mem_read(base.HEAP, emu.brk - base.HEAP))
runs = [(mm.start(), mm.group()) for mm in
        re.finditer(rb"[A-Za-z0-9_\-{}\"\.:/]{120,}", heap)]
runs.sort(key=lambda t: -len(t[1]))
print("longest ASCII runs in heap:")
seen = set()
for pos, r in runs[:6]:
    if r[:60] in seen:
        continue
    seen.add(r[:60])
    print("  @%#x len=%d: %s" % (base.HEAP + pos, len(r), r.decode("latin1")))

# where does the nonce live in emu RAM (for potential later forcing)?
locs = []
off = heap.find(nonce12[:8])
while off != -1:
    locs.append(base.HEAP + off)
    off = heap.find(nonce12[:8], off + 1)
stack = bytes(emu.uc.mem_read(base.STACK, base.STACK_SZ))
slocs = []
off = stack.find(nonce12[:8])
while off != -1:
    slocs.append(base.STACK + off)
    off = stack.find(nonce12[:8], off + 1)
print("nonce[0:8] heap locs:", [hex(x) for x in locs], "stack locs:", [hex(x) for x in slocs])

# ---- pure cross-check: same map, same second, the EMU's own nonce ------------
claims = ap.build_claims("session", m, client_sdk="android5.6.0",
                         include_block2=True)
pure = ap.sign(SEC, nonce12, claims, None)
same = pure == blob
print("pure(sign, emu-nonce, marker map) == emu blob:", same)
if not same:
    fd = next((j for j in range(304) if pure[j] != blob[j]), None)
    print("  first diff:", fd)
    print("  pure rec:", cbc := None)
print("claims len:", len(claims))
print("claims:", claims.decode("latin1"))
json.dump({"srand": emu.srand_log, "n_rand": len(emu.rand_log),
           "nonce12": nonce12.hex(), "blob": out.hex().upper(),
           "record": s, "claims": claims.decode("latin1"),
           "pure_matches_emu": same,
           "nonce_heap_locs": locs, "nonce_stack_locs": slocs},
          open(os.path.join(HERE, "soverify_probe1_out.json"), "w"), indent=1)
