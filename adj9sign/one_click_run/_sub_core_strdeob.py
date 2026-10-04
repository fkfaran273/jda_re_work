"""_sub_core_strdeob.py — decode the obfuscated string blobs in the iOS core
__DATA,__data (0x1d5340..0x1d6b50) and dump __DATA,__cfstring entries.

Method: for each printable run, try single-byte XOR 0..255 and Caesar shifts;
score by charset plausibility + known keyword hits; print best candidates.
"""
import os
import re
import struct
import sys
import base64

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _sub_core_macho as macho

IOS_DEV = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins/extracted/xcframework_dyn/AdjustSigSdk.xcframework/ios-arm64/AdjustSigSdk.framework/AdjustSigSdk"

KEYWORDS = ["client_sdk", "endpoint", "activity_kind", "control_params",
            "adj_signing_id", "headers_id", "native_version", "secret_id",
            "algorithm", "os_name", "os_version", "idfv", "idfa", "receipt",
            "locale", "timezone", "package", "params", "signature", "sign",
            "payload", "signature_id", "app_secret", "info", "environment",
            "sandbox", "production", "1.2.840", "sha256", "sha-256", "md5",
            "adjust", "com.adjust", "sdk", "ios", "detail", "appstore",
            "PKCS", "pkcs", "cms", "CMS", "OID", "key", "cert"]


def score(txt):
    good = sum(1 for c in txt if c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.=/ -',%:{}()<>+")
    kw = sum(2 if k in txt else 0 for k in KEYWORDS)
    return good - 0.3 * len(txt) + kw * 3


def main():
    s = macho.slices(IOS_DEV)[0]
    data = s.data
    # __cfstring dump
    for seg, sec in s.sections():
        if sec["sect"] == "__cfstring":
            off = sec["fileoff"]
            n = sec["size"] // 32
            print(f"== __cfstring ({n} entries)")
            for i in range(n):
                e = off + 32 * i
                isa, flags, ptr, ln = struct.unpack_from("<QQQQ", data, e - sec["fileoff"] + 0) if False else struct.unpack_from("<QQQQ", s.data, e)
                # data is slice-relative already
            break
    # simpler: parse cfstring in slice data
    for seg, sec in s.sections():
        if sec["sect"] == "__cfstring":
            fo = sec["fileoff"]
            for i in range(sec["size"] // 32):
                isa, flags, ptr, ln = struct.unpack_from("<QQQQ", s.data, fo + 32 * i)
                # ptr is VM addr of string; find file offset
                vmaddr = None
                foff = None
                for sg2, sc in s.sections():
                    if sc["addr"] <= ptr < sc["addr"] + sc["size"]:
                        foff = sc["fileoff"] + (ptr - sc["addr"])
                        break
                txt = ""
                if foff is not None:
                    end = s.data.find(b"\x00", foff)
                    txt = s.data[foff:end].decode("utf-8", "replace")
                print(f"  [{i:2d}] @{fof if False else hex(fo + 32*i)} -> ptr {ptr:#x} (file {hex(foff) if foff else '-'}) len {ln}: {txt!r}")
            break

    # obfuscated strings in __DATA,__data
    for seg, sec in s.sections():
        if sec["sect"] == "__data":
            fo, sz = sec["fileoff"], sec["size"]
            break
    blob = s.data[fo:fo + sz]
    runs = [(m.start() + fo, m.group().decode()) for m in
            re.finditer(rb"[\x20-\x7e]{6,}", blob)]
    print(f"\n== printable runs in __DATA,__data ({len(runs)})")
    for off, txt in runs:
        cands = []
        for k in range(256):
            dec = "".join(chr(ord(c) ^ k) for c in txt)
            if all(32 <= ord(c) < 127 for c in dec):
                cands.append((score(dec), f"xor{k:#04x}", dec))
        for k in range(256):
            dec = "".join(chr((ord(c) - 32 + k) % 95 + 32) for c in txt)
            cands.append((score(dec) * 0.5, f"caesar{k}", dec))
        cands.sort(reverse=True)
        best = cands[:2]
        print(f"  {off:#08x} {txt!r}")
        for sc, how, dec in best:
            print(f"        {how:<10} score={sc:6.1f}  {dec!r}")

    # the __const blob at 0x1cb4b8: 'CB3gdYWw743YjPpMiyMTiHWQ 5.0.0'
    print("\n== __const blob @0x1cb4b8")
    b = s.data[0x1cb4b8:0x1cb508]
    print("raw:", b.hex())
    print("ascii:", b.decode("ascii", "replace"))
    m = re.match(rb"([A-Za-z0-9+/=]+)", b)
    if m:
        try:
            dec = base64.b64decode(m.group(1) + b"=" * (-len(m.group(1)) % 4))
            print("b64 decoded:", dec.hex(), repr(dec))
            for k in range(256):
                x = bytes(c ^ k for c in dec)
                try:
                    t = x.decode("utf-8")
                    if all(32 <= ord(c) < 127 for c in t):
                        print(f"   xor{k:#04x}: {t!r}")
                except UnicodeDecodeError:
                    pass
        except Exception as e:
            print("b64 fail:", e)


if __name__ == "__main__":
    main()
