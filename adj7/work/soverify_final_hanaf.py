"""soverify_final_hanaf.py -- final hanaf-libsigner emulation, one process:
  A. marker-map probe (all pool keys set, like reference R1) on the HANAF
     lib -> claims emission vs reference, secret_id question.
  B. cross-mint: hanaf lib signing the REAL captured session map
     (hanaf_map.json captures[0], sec=1791365799) vs adj7_pure.sign.

Raw artifacts are dumped to disk IMMEDIATELY after each emu run (the two
prior runs were lost to post-processing bugs, never the lib).
"""
import contextlib
import hashlib
import hmac
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

# ---- emu module against the hanaf lib ----------------------------------------
src = open(os.path.join(WORK, "adj7s3_emu.py"), encoding="utf-8").read()
src = src.replace(
    'SO = "bins/adjust-android-signature-3.62/jni/arm64-v8a/libsigner.so"',
    'SO = r"%s"' % os.path.join(HERE, "hanaf_libsigner.so"))
src = src.replace("0xa95ac", "0x9afc0")
assert "hanaf_libsigner.so" in src and "0x9afc0" in src
emu_mod = type(sys)("emu_hanaf")
emu_mod.__dict__["__name__"] = "emu_hanaf"
exec(compile(src, "adj7s3_emu_hanaf", "exec"), emu_mod.__dict__)
emu_mod.PKG = "in.hanafintech"


class ProbeEmu(emu_mod.Emu):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.out_buf = None
        self.rand_log = []
        self.srand_log = []
        self.set208 = []
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
            self.srand_log.append(uc.reg_read(UC_ARM64_REG_X0))
        return super().plt_dispatch(uc, name)

    def jni_call(self, uc, idx, x):
        if idx == 208:
            self.set208.append((x[1], x[2], x[3], x[4]))
        return super().jni_call(uc, idx, x)


# ---- record inverse (spn_chunk^-1) --------------------------------------------
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


def recover_record(out, nblocks):
    rec, prev = b"", out[:16]
    for k in range(16, 16 + 16 * nblocks, 16):
        c = out[k:k + 16]
        rec += bytes(a ^ b for a, b in zip(unspn(c, ap._RK), prev))
        prev = c
    return rec


def parse_rec(rec):
    s = rec.split(b"\x00")[0].decode("latin1", "replace")
    a = int(re.search(r'"a":\s*(\d+)', s).group(1))
    b_ = re.search(r'"b":\s*"([0-9A-Fa-f]+)"', s).group(1)
    c40 = re.search(r'"c":\s*"([^"]*)"', s).group(1)
    d8 = re.search(r'"d":\s*"([0-9A-Fa-f]{8})"', s).group(1)
    me = re.search(r'"e":\s*"([^"]*)"', s)
    nonce12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
    cert40 = c40.encode("latin1") if c40.strip("\x000") else None
    return s, nonce12, b_, cert40, (me.group(1) if me else None)


def tag_bodies(out):
    hits = []
    n = len(out)
    L = 16
    while 16 + L + 32 <= n:
        if hmac.new(ap.DK37, out[16:16 + L],
                    hashlib.sha256).digest() == out[16 + L:16 + L + 32]:
            hits.append(L)
        L += 16
    return hits


def heap_bytes(emu):
    return bytes(emu.uc.mem_read(emu_mod.HEAP, emu.brk - emu_mod.HEAP))


def run_phase(name, sec, mapobj):
    emu = ProbeEmu(verbose=False)
    emu.fixed_time = sec
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ret = emu.run(payload=bytes(32), mapobj=dict(mapobj))
    log = buf.getvalue()
    # ---- dump raw artifacts FIRST ----
    open(os.path.join(HERE, "soverify_final_%s_out.bin" % name),
         "wb").write(bytes(ret) if ret else b"")
    open(os.path.join(HERE, "soverify_final_%s_heap.bin" % name),
         "wb").write(heap_bytes(emu))
    cands = []
    if ret:
        cands.append(bytes(ret))
    for ref, start, ln, bufaddr in emu.set208:
        o = emu.heap_objs.get(ref)
        if o is not None and o.val is not None:
            cands.append(bytes(o.val))
    print("=" * 20, "phase", name, "=" * 20)
    print("srand:", emu.srand_log, "| rand draws:", len(emu.rand_log))
    print("set208 (arr,start,len):",
          [(hex(a), s, l) for a, s, l, _ in emu.set208])
    print("candidate outputs:", [len(c) for c in cands])
    return emu, log, cands


def interpret(out, sec, claims_vars, label):
    """tag-split interpretation + record decode + H-law tests."""
    res = {"len": len(out)}
    hits = tag_bodies(out)
    res["tag_valid_bodies"] = hits
    print("%s: len=%d tag-valid body lens: %s" % (label, len(out), hits))
    if not hits:
        return res
    L = hits[0]
    rec = recover_record(out, L // 16)
    s, nonce, H, cert, e = parse_rec(rec)
    pfx = cert if cert is not None else b"\x00" * 40
    print("  record:", s[:120], "..." if len(s) > 120 else "")
    print("  nonce12:", nonce.hex(), "| e-field:",
          "ABSENT" if e is None else e[:16] + "...")
    print("  cert40:", "NULs" if cert is None else cert.decode("latin1"))
    print("  header == make_header(%d):" % sec,
          bytes(out[:16]) == ap.make_header(sec))
    res.update({"body": L, "record": s, "nonce12": nonce.hex(),
                "H": H, "e": e,
                "cert40": None if cert is None else cert.decode("latin1"),
                "header_eq": bytes(out[:16]) == ap.make_header(sec)})
    for nm, cv in claims_vars.items():
        res["H==+SHA0:" + nm] = (H == ap.sha256_iv0(
            pfx + nonce + ap.SHA0_HEX.encode() + cv).hex().upper())
        res["H==-SHA0:" + nm] = (H == ap.sha256_iv0(
            pfx + nonce + cv).hex().upper())
        print("  H == law(+SHA0) over [%s]:" % nm,
              res["H==+SHA0:" + nm],
              "| law(-SHA0):", res["H==-SHA0:" + nm])
    return res, rec, nonce, cert, L


# ########### PHASE A: marker map (identical to reference R1) ##################
POOL = list(ap.CLAIM_POOL)
SPECIAL = {"seq": "SQV", "secret_id": "SIDV", "package_name": "PKGV",
           "session_count": "SCV", "app_token": "APPV", "created_at": "CRV",
           "partner_params": "PPV"}
EMPTY = {"params", "payload", "details", "sharing", "measurement"}
mA = {}
for i, k in enumerate(POOL):
    if k in SPECIAL:
        mA[k] = SPECIAL[k]
    elif k in EMPTY:
        mA[k] = ""
    else:
        mA[k] = "K%02d" % i
mA["zzz_not_in_pool"] = "ZNP"
mA["endpoint"] = "EPV"
mA["language"] = "LANG"
mA["attribution_deeplink"] = "ADLINK"
mA["activity_kind"] = "session"
mA["client_sdk"] = "android5.6.0"

SEC_A = 1791365803
RES = {}
try:
    emuA, logA, candsA = run_phase("A", SEC_A, mA)
    claims_with = ap.build_claims("session", mA, client_sdk="android5.6.0",
                                  include_block2=True)
    pool_nosecret = [k for k in POOL if k != "secret_id"]
    split = pool_nosecret.index("seq")
    profile, tail, block2 = (pool_nosecret[:split], pool_nosecret[split:-2],
                             pool_nosecret[-2:])
    parts = []
    for k in profile:
        if mA.get(k) not in (None, ""):
            parts.append(str(mA[k]).encode("latin1"))
    parts.append(b"1300000")
    for k in tail:
        if mA.get(k) not in (None, ""):
            parts.append(str(mA[k]).encode("latin1"))
    for k in block2:
        if mA.get(k) not in (None, ""):
            parts.append(str(mA[k]).encode("latin1"))
    claims_wo = b"".join(parts)
    heapA = heap_bytes(emuA)
    print("heap contains claims WITH secret_id:", heapA.count(claims_with))
    print("heap contains claims W/O  secret_id:", heapA.count(claims_wo))
    runs = [(mm.start(), mm.group()) for mm in
            re.finditer(rb"[A-Za-z0-9_\-{}\"\.:/]{120,}", heapA)]
    runs.sort(key=lambda t: -len(t[1]))
    for pos, r in runs[:4]:
        if r.startswith(b"K00K01"):
            print("native claims buffer (%d chars):" % len(r))
            print("  ", r.decode("latin1"))
    mr = emuA.map_reads
    ck = sorted({k[1:] for k in mr
                 if isinstance(k, str) and k.startswith("?")})
    gt = sorted({k for k in mr
                 if isinstance(k, str) and not k.startswith("?")})
    print("containsKey unique:", len(ck), "| secret_id in containsKey:",
          "secret_id" in ck)
    print("get unique:", len(gt), "| secret_id in get:", "secret_id" in gt)
    RES["A"] = {"heap_with": heapA.count(claims_with),
                "heap_wo": heapA.count(claims_wo),
                "ck_n": len(ck), "ck_secret_id": "secret_id" in ck,
                "gt_n": len(gt), "gt_secret_id": "secret_id" in gt}
    for c in candsA:
        r = interpret(c, SEC_A, {"with": claims_with, "wo": claims_wo},
                      "A-out%d" % len(c))
        RES["A"]["interp_len%d" % len(c)] = r
except Exception as ex:
    import traceback
    traceback.print_exc()
    RES["A"] = {"error": repr(ex)}

# ########### PHASE B: cross-mint on the real session map ######################
try:
    cap = json.load(open(os.path.join(HERE, "hanaf_map.json")))["captures"][0]
    mB = {str(k): str(v) for k, v in cap["map"].items()}
    SEC_B = 1791365799
    hooks = json.load(open(os.path.join(HERE, "soverify_hook_parsed.json")))
    hook0 = hooks[0]
    claims_hook = bytes.fromhex(hook0["claims_hex"])

    emuB, logB, candsB = run_phase("B", SEC_B, mB)
    expB = ap.build_claims("session", mB, client_sdk="android5.6.0",
                           include_block2=True)
    heapB = heap_bytes(emuB)
    print("build_claims(session map) == hook claims_hex:", expB == claims_hook,
          "| lens:", len(expB), len(claims_hook))
    print("heap contains hook claims:", heapB.count(claims_hook))
    RES["B"] = {"claims_eq_hook": expB == claims_hook,
                "heap_claims": heapB.count(claims_hook)}
    for c in candsB:
        r = interpret(c, SEC_B, {"hook": expB}, "B-out%d" % len(c))
        RES["B"]["interp_len%d" % len(c)] = r
        if "body" not in r:
            continue
        L = r["body"]
        nonceB = bytes.fromhex(r["nonce12"])
        certB = r["cert40"] and r["cert40"].encode("latin1")
        if L == 256:
            pure = ap.sign(SEC_B, nonceB, expB, certB)
            print("CROSS-MINT pure(304) == hanaf-emu blob:", pure == c)
            RES["B"]["pure_eq_emu"] = (pure == c)
        else:
            # rebuild the variant record/body/tag with pure primitives
            pfx = certB if certB is not None else b"\x00" * 40
            law_sha0 = r.get("H==+SHA0:hook")
            H = ap.sha256_iv0(pfx + nonceB
                              + (ap.SHA0_HEX.encode() if law_sha0 else b"")
                              + expB)
            A = str(int.from_bytes(nonceB[0:8], "little")).rjust(20).encode()
            d8 = nonceB[8:12].hex().upper().encode()
            j = (b'{ "a":  ' + A + b' ,"b": "' + H.hex().upper().encode()
                 + b'","c": "' + pfx + b'","d": "' + d8 + b'" }\x00')
            rec = j + b"\x10" * (L - len(j))
            header = ap.make_header(SEC_B)
            body = ap.cbc_encrypt(rec, header)
            blob = header + body + hmac.new(ap.DK37, body,
                                            hashlib.sha256).digest()
            print("CROSS-MINT pure variant(%dB, law_sha0=%s) == emu:"
                  % (16 + L + 32, law_sha0), blob == c)
            RES["B"]["pure_variant_eq_emu"] = (blob == c)
        dev = ap.sign(hook0["sec_used"], bytes.fromhex(hook0["nonce12"]),
                      claims_hook, hook0["cert40"].encode())
        print("anchor: pure == genuine device blob:",
              dev == bytes.fromhex(hook0["blob_hex"]))
        RES["B"]["anchor_dev"] = (dev == bytes.fromhex(hook0["blob_hex"]))
except Exception as ex:
    import traceback
    traceback.print_exc()
    RES["B"] = {"error": repr(ex)}

json.dump(RES, open(os.path.join(HERE, "soverify_final_hanaf_out.json"),
                    "w"), indent=1)
print("done")
