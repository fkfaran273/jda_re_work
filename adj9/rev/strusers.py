"""For each crypto/keystore string, find every code site that LOADS it
(adrp + ldr/add with the matching page+offset). The loading function is the
consumer, whether or not it uses the canonical in-place-decrypt pattern."""
import os
import sys
import pickle
from collections import defaultdict

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF  # noqa: E402
from decryptors import LIB  # noqa: E402
from dataref2 import build, xrefs  # noqa: E402

WANT = [
    "javax/crypto/Cipher", "getInstance", "RSA/ECB/PKCS1Padding", "AES",
    "javax/crypto/spec/SecretKeySpec", "HmacSHA256", "key2", "AndroidKeyStore",
    "java/security/KeyStore", "getKey", "javax/crypto/Mac", "android/util/Base64",
    "decode", "java/security/MessageDigest", "generateKeyPair", "setAttestationChallenge",
    "getCertificateChain", "KeyFactory", "toByteArray", "adjust_keys", "encrypted_key",
    "doFinal", "init", "update", "getEncoded", "Ed25519",
]


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    strings = pickle.load(open("strings_final.pkl", "rb"))
    insns, callees, imports = pickle.load(open("nsign_cfg.pkl", "rb"))
    inset = set(insns)

    print("disassembling .text ...", file=sys.stderr)
    allins = build(e, md)
    print("%d insns" % len(allins), file=sys.stderr)

    # string start -> text
    starts = {}
    for va, v in strings.items():
        s = v[-1] if isinstance(v, (tuple, list)) and isinstance(v[-1], str) else \
            (v.get("text", "") if isinstance(v, dict) else str(v))
        starts[va] = s

    # targets: string start, and start+/- small offsets inside it
    targets = {}
    for va, s in starts.items():
        if not any(w in s for w in WANT):
            continue
        for off in range(0, min(len(s) + 1, 64), 16):
            targets[va + off] = (va, s, off)

    res = xrefs(allins, set(targets), md)

    agg = defaultdict(set)
    for tg, addrs in res.items():
        va, s, off = targets[tg]
        for a in addrs:
            agg[(va, s)].add(a)

    print("\n=== code sites loading crypto/keystore strings ===\n")
    rows = []
    for (va, s), addrs in agg.items():
        on = sum(1 for a in addrs if a in inset)
        rows.append((s, va, sorted(addrs), on, len(addrs)))
    for s, va, addrs, on, tot in sorted(rows, key=lambda r: -r[3]):
        flag = "***" if on else "   "
        print("%s %-40s data@0x%-8x %3d site(s), %3d on nSign path" %
              (flag, s.replace("\n", " ")[:40], va, tot, on))
        for a in addrs[:8]:
            print("       0x%x %s" % (a, "[ON]" if a in inset else ""))


if __name__ == "__main__":
    main()
