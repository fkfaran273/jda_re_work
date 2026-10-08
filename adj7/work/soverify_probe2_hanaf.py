"""soverify_probe2_hanaf.py -- R2: marker-map probe on the HANAFINTECH
libsigner.so (the binary actually shipped in in.hanafintech's APK).

Loads adj7s3_emu.py with SO patched to the extracted APK lib and the nSign
entry patched to its vaddr (0x9afc0).  Same marker map as R1.  Decodes the
native claims buffer, recovers the emu nonce, cross-checks pure (with AND
without secret_id), and dumps the containsKey/get trace.
"""
import contextlib
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
WORK = r"C:\Users\Apps\Downloads\com.penti.app\adj7_work"
sys.path.insert(0, WORK)

import adj7_pure as ap  # noqa: E402

SEC = 1791365803

# ---- load the emu module against the hanaf lib -------------------------------
src = open(os.path.join(WORK, "adj7s3_emu.py"), encoding="utf-8").read()
src = src.replace(
    'SO = "bins/adjust-android-signature-3.62/jni/arm64-v8a/libsigner.so"',
    'SO = r"%s"' % os.path.join(HERE, "hanaf_libsigner.so"))
src = src.replace("0xa95ac", "0x9afc0")
assert "hanaf_libsigner.so" in src and "0x9afc0" in src
emu_mod = type(sys)("emu_hanaf")
emu_mod.__dict__["__name__"] = "emu_hanaf"
exec(compile(src, "adj7s3_emu_hanaf", "exec"), emu_mod.__dict__)

POOL = list(ap.CLAIM_POOL)
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
m["zzz_not_in_pool"] = "ZNP"
m["endpoint"] = "EPV"
m["language"] = "LANG"
m["attribution_deeplink"] = "ADLINK"
m["activity_kind"] = "session"
m["client_sdk"] = "android5.6.0"


class ProbeEmu(emu_mod.Emu):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.out_buf = None
        self.rand_log = []
        self.srand_log = []
        self.errno_addr = self.alloc(64)
        self.uc.mem_write(self.errno_addr, bytes(64))
        self.open_fds = {}

    def plt_dispatch(self, uc, name):
        from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                        UC_ARM64_REG_X2, UC_ARM64_REG_LR,
                                        UC_ARM64_REG_PC)
        if name == "__errno":
            uc.reg_write(UC_ARM64_REG_X0, self.errno_addr)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if name == "strtol":
            a = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                          UC_ARM64_REG_X2)]
            s = self.read_cstr(a[0]).decode("latin1", "replace").strip()
            try:
                v = int(s, a[2] or 10)
            except ValueError:
                v = 0
            uc.reg_write(UC_ARM64_REG_X0, v & 0xFFFFFFFFFFFFFFFF)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if name in ("readdir", "opendir", "closedir"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if name in ("readlink", "open", "__open_2"):
            if name in ("open", "__open_2"):
                path = self.read_cstr(
                    uc.reg_read(UC_ARM64_REG_X0)).decode("latin1", "replace")
                content = self.vfs.get(path)
                if content is not None:
                    fh = 0xF2000000 + len(self.open_fds) * 8 + 8
                    self.open_fds[fh] = [content, 0]
                    uc.reg_write(UC_ARM64_REG_X0, fh)
                    uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
                    return
            uc.reg_write(UC_ARM64_REG_X0, 0xFFFFFFFFFFFFFFFF)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if name == "read":
            a = [uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1),
                 uc.reg_read(UC_ARM64_REG_X2)]
            e = self.open_fds.get(a[0])
            if e is None:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                content, pos = e
                chunk = content[pos:pos + a[2]]
                uc.mem_write(a[1], chunk)
                e[1] += len(chunk)
                uc.reg_write(UC_ARM64_REG_X0, len(chunk))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if name == "getauxval":
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if name == "rand":
            self.rand_log.append(1)
        elif name == "srand":
            from unicorn.arm64_const import UC_ARM64_REG_X0 as _X0
            self.srand_log.append(uc.reg_read(_X0))
        return super().plt_dispatch(uc, name)

    def jni_call(self, uc, idx, x):
        if idx == 208 and self.out_buf is None and x[3] == 304:
            self.out_buf = x[4]
        return super().jni_call(uc, idx, x)


emu = ProbeEmu(verbose=False)
emu.fixed_time = SEC
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    out = emu.run(payload=bytes(32), mapobj=m)
    if emu.out_buf is not None:
        cand = bytes(emu.uc.mem_read(emu.out_buf, 304))
        if out is None or len(out) != 304:
            out = cand
log = buf.getvalue()
print("out len:", len(out) if out else None,
      "| tag ok:", ap.verify_tag(out) if out and len(out) == 304 else None)
print("blob:", out.hex().upper()[:64] if out else "NONE")
print("srand:", emu.srand_log, "rand draws:", len(emu.rand_log))
if out is None:
    print("---- emu log tail ----")
    print("\n".join(log.splitlines()[-40:]))
    sys.exit(1)

# ---- recover record/nonce ----------------------------------------------------
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
prev = out[:16]
for k in range(16, 272, 16):
    c = out[k:k + 16]
    rec += bytes(a ^ b for a, b in zip(unspn(c, ap._RK), prev))
    prev = c
s = rec.decode("latin1", "replace")
a = int(re.search(r'"a":\s*(\d+)', s).group(1))
d8 = re.search(r'"d":\s*"([0-9A-Fa-f]{8})"', s).group(1)
c40 = re.search(r'"c":\s*"([^"]*)"', s).group(1)
cert40 = c40.encode("latin1") if c40.strip("\x000") else None
nonce12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
print("record a-width:", len(str(a)), "nonce12:", nonce12.hex(),
      "cert40:", "NULs" if cert40 is None else c40)

# ---- claims buffer -----------------------------------------------------------
heap = bytes(emu.uc.mem_read(emu_mod.HEAP, emu.brk - emu_mod.HEAP))
runs = [(mm.start(), mm.group()) for mm in
        re.finditer(rb"[A-Za-z0-9_\-{}\"\.:/]{120,}", heap)]
runs.sort(key=lambda t: -len(t[1]))
native_claims = None
for pos, r in runs[:6]:
    if r.startswith(b"K00K01"):
        native_claims = r.decode("latin1")
        print("native claims @%#x len=%d:" % (emu_mod.HEAP + pos, len(r)))
        print("  ", native_claims)
for probe in (b"SIDV", b"secret_id"):
    print("heap occurrences of %r:" % probe, heap.count(probe))

# query trace
mr = emu.map_reads
qs = [k for k in mr if isinstance(k, str)]
print("total map queries:", len(mr), "| queries secret_id:", "secret_id" in qs)
print("queried keys (first pass, unique, in order):")
seen = []
for k in qs:
    if k not in seen:
        seen.append(k)
print("  n_unique =", len(seen))
print("  'secret_id' in unique:", "secret_id" in seen,
      "| 'seq' at:", seen.index("seq") if "seq" in seen else None,
      "| neighbors:", seen[seen.index("seq") - 2:seen.index("seq") + 3] if "seq" in seen else None)

# ---- pure cross-check --------------------------------------------------------
claims_with = ap.build_claims("session", m, client_sdk="android5.6.0",
                              include_block2=True)
pool_nosecret = [k for k in POOL if k != "secret_id"]
split = pool_nosecret.index("seq")
profile, tail, block2 = pool_nosecret[:split], pool_nosecret[split:-2], pool_nosecret[-2:]
parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
parts.append("1300000")
parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
parts += [str(m[k]) for k in block2 if m.get(k) not in (None, "")]
claims_wo = "".join(parts).encode("latin1")
print("claims_wo == native buffer:", claims_wo.decode("latin1") == native_claims)
print("pure WITH secret_id == emu blob:", ap.sign(SEC, nonce12, claims_with, cert40) == out)
print("pure W/O  secret_id == emu blob:", ap.sign(SEC, nonce12, claims_wo, cert40) == out)

json.dump({"blob": out.hex().upper(), "nonce12": nonce12.hex(),
           "native_claims": native_claims, "srand": emu.srand_log,
           "rand_draws": len(emu.rand_log),
           "queries_secret_id": "secret_id" in qs,
           "unique_query_count": len(seen)},
          open(os.path.join(HERE, "soverify_probe2_out.json"), "w"), indent=1)
