"""_sub_core_claimkeys.py — targeted decode of claim-key strings inside the
iOS core __DATA,__data: brute single-byte XOR / ADD / SUB for every printable
run and match against a claim-key / signature-vocabulary dictionary.
"""
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _sub_core_macho as macho

IOS_DEV = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins/extracted/xcframework_dyn/AdjustSigSdk.xcframework/ios-arm64/AdjustSigSdk.framework/AdjustSigSdk"

TARGETS = ["secret_id", "headers_id", "adj_signing_id", "client_sdk",
           "activity_kind", "endpoint", "control_params", "native_version",
           "os_name", "os_version", "algorithm", "signature", "signing",
           "idfv", "idfa", "receipt", "locale", "timezone", "payload",
           "params", "package", "environment", "sandbox", "production",
           "simulat", "sha256", "sha-256", "digest", "whiten", "block",
           "record", "header", "claim", "key", "version", "certificat",
           "attribut", "subject", "issuer", "signer", "message", "ASN1",
           "OID", "1.2.840", "pkcs", "PKCS", "rsaEncryption", "signedData",
           "appStore", "Bundle", "guid", "uuid", "UUID", "vendor"]


def variants(txt):
    for k in range(256):
        yield (f"xor{k:#04x}", "".join(chr(ord(c) ^ k) for c in txt))
    for k in range(1, 95):
        yield (f"sub{k}", "".join(chr((ord(c) - 32 - k) % 95 + 32) for c in txt))
        yield (f"add{k}", "".join(chr((ord(c) - 32 + k) % 95 + 32) for c in txt))


def main():
    s = macho.slices(IOS_DEV)[0]
    for seg, sec in s.sections():
        if sec["sect"] == "__data":
            fo, sz = sec["fileoff"], sec["size"]
            break
    blob = s.data[fo:fo + sz]
    runs = [(m.start() + fo, m.group().decode()) for m in
            re.finditer(rb"[\x20-\x7e]{4,}", blob)]
    seen = set()
    print("== targeted decodes (claim-key vocabulary) ==")
    for off, txt in runs:
        best = []
        for how, dec in variants(txt):
            hits = [t for t in TARGETS if t in dec]
            if hits:
                best.append((len(hits), how, dec, hits))
        best.sort(reverse=True)
        if best:
            _, how, dec, hits = best[0]
            key = (txt, dec)
            if key in seen:
                continue
            seen.add(key)
            print(f"  {off:#08x} {txt!r}")
            print(f"      -> {how:<8} {dec!r}   hits={hits}")

    # also scan the WHOLE binary for 'secret_id' under xor 0x0F siblings:
    # any 12..40-byte run whose XOR-k decode ends with _id / contains keys
    print("\n== whole-file claim-key scan (x/add/sub) ==")
    whole = s.data
    for m in re.finditer(rb"[\x20-\x7e]{6,48}", whole):
        txt = m.group().decode()
        for how, dec in variants(txt):
            for t in ("secret_id", "headers_id", "adj_signing_id",
                      "client_sdk", "activity_kind", "control_params",
                      "native_version", "os_name"):
                if t in dec:
                    print(f"  {m.start():#09x} {txt!r} -> {how} {dec!r}")
                    break
        else:
            continue


if __name__ == "__main__":
    main()
