# Fresh APK v2/v3 signing-block parser -> signer cert DERs + SHA1
import sys, hashlib, struct

def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

def find_cd_start(apk):
    d = apk
    i = d.rfind(b"PK\x05\x06")          # EOCD
    if i < 0:
        raise SystemExit("no EOCD")
    cd_off = u32(d, i + 16)
    return cd_off

def signing_block(apk):
    cd = find_cd_start(apk)
    magic_off = cd - 16
    assert apk[magic_off:magic_off + 16] == b"APK Sig Block 42", "no sig block"
    blk_size = u64(apk, cd - 24)          # counts pairs + footer size + magic
    start = cd - 8 - blk_size             # leading size field
    assert u64(apk, start) == blk_size
    return start + 8, cd - 24             # pairs region

def pairs(apk):
    s, e = signing_block(apk)
    o = s
    while o < e:
        ln = u64(apk, o)
        pid = u32(apk, o + 8)
        yield pid, apk[o + 12: o + 8 + ln]
        o += 8 + ln

def _parse_signers(val, base_off):
    res = []
    o = base_off
    signers_len = min(u32(val, o), len(val) - 4); o += 4
    end = min(o + signers_len, len(val))
    while o + 4 <= end:
        try:
            signer_len = u32(val, o); o += 4
            sd_len = u32(val, o)
            if sd_len > len(val) - o - 4:
                break
            sd = val[o + 4: o + 4 + sd_len]; o += 4 + sd_len
            p = 0
            digests_len = u32(sd, p); p += 4 + digests_len
            certs_len = u32(sd, p); p += 4
            cend = min(p + certs_len, len(sd))
            certs = []
            while p + 4 <= cend:
                clen = u32(sd, p); p += 4
                if clen > cend - p:
                    break
                certs.append(sd[p: p + clen]); p += clen
            if certs and all(c[:2] == b"\x30\x82" for c in certs):
                res.append(certs)
        except Exception:
            break
    return res

def v2_signer_certs(val):
    return _parse_signers(val, 0)

def v3_signer_certs(val):
    # v3: try leading signers-length at 0 (per spec) then at 4
    try:
        r = _parse_signers(val, 0)
        if r:
            return r
    except Exception:
        pass
    return _parse_signers(val, 4)

def dump(apk_path, tag):
    apk = open(apk_path, "rb").read()
    print("== %s (%d B)" % (tag, len(apk)))
    for pid, val in pairs(apk):
        nm = {0x7109871a: "v2", 0xf05368c0: "v3", 0x42726577: "dep", 0x2146444e: "ver1"}.get(pid, hex(pid))
        if pid in (0x7109871a, 0xf05368c0):
            fn = v2_signer_certs if pid == 0x7109871a else v3_signer_certs
            for k, certs in enumerate(fn(val)):
                for j, c in enumerate(certs):
                    h = hashlib.sha1(c).hexdigest().upper()
                    print("  %s signer%d cert%d: %d B sha1=%s" % (nm, k, j, len(c), h))
                    open(r"..\apks\certs\%s_%s_s%d_c%d.der" % (tag, nm, k, j), "wb").write(c)
        else:
            print("  block %s (%d B)" % (nm, len(val)))

import os
os.makedirs(r"..\apks\certs", exist_ok=True)
dump(r"..\apks\hanaf_base.apk", "hanaf")
dump(r"..\apks\mitra_base.apk", "mitra")
