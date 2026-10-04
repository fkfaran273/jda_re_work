"""Map each obfuscated .data string to the code site that decrypts it.

The strings are decrypted *in place by the code that uses them*, so the
enclosing function of a decrypt site is the consumer of that string.
Focus on the crypto/keystore strings: whoever decrypts "Cipher",
"RSA/ECB/PKCS1Padding", "AES", "SecretKeySpec", "HmacSHA256", "key2"
is the encryptor we are hunting.
"""
import os
import sys
import pickle

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF  # noqa: E402
from decryptors import LIB  # noqa: E402

INTEREST = [
    "javax/crypto/Cipher", "RSA/ECB/PKCS1Padding", "AES",
    "javax/crypto/spec/SecretKeySpec", "HmacSHA256", "key2",
    "AndroidKeyStore", "java/security/KeyStore", "getKey",
    "javax/crypto/Mac", "android/util/Base64", "java/security/MessageDigest",
    "generateKeyPair", "KeyPairGenerator", "setAttestationChallenge",
    "getCertificateChain", "KeyFactory", "toByteArray", "Ed25519", "EC", "RSA",
    "adjust_keys", "encrypted_key", "environment",
]


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    strings = pickle.load(open("strings_final.pkl", "rb"))
    text_by_va = {}
    for va, v in strings.items():
        s = v[-1] if isinstance(v, (tuple, list)) and isinstance(v[-1], str) else \
            (v.get("text", "") if isinstance(v, dict) else str(v))
        text_by_va[va] = s

    _sites, dec = pickle.load(open("decrypt.pkl", "rb"))
    # dec : {data_va: (addr_lo, addr_hi)}
    va_to_str = {}
    for va in dec:
        # the string entry whose [start, start+len+1) covers this access
        cands = [v for v in text_by_va if v <= va < v + len(text_by_va[v]) + 1]
        if cands:
            b = max(cands)
            va_to_str[va] = (b, text_by_va[b])
        else:
            cands = [v for v in text_by_va if v <= va]
            if cands:
                b = max(cands)
                va_to_str[va] = (b, text_by_va[b] + "   [near, len=%d]" % (va - b))

    insns, callees, imports = pickle.load(open("nsign_cfg.pkl", "rb"))
    inset = set(insns)

    t = e.byname[".text"]
    lo, hi = t["addr"], t["addr"] + t["size"]

    def func_entry(a):
        v = a
        off0 = e.vaddr_to_off(max(lo, a - 0x4000))
        base = max(lo, a - 0x4000)
        dis = list(md.disasm(e.data[off0:off0 + (a - base) * 4 + 4], base))
        for i in reversed(dis):
            if i.mnemonic == "stp" and "x29" in i.op_str and "x30" in i.op_str:
                return i.address
        return None

    print("=== decrypt sites for crypto/keystore strings ===\n")
    rows = []
    for va, (alo, ahi) in sorted(dec.items()):
        if va not in va_to_str:
            continue
        base, s = va_to_str[va]
        if not any(k in s for k in INTEREST):
            continue
        fe = func_entry(alo)
        on = "ON " if alo in inset else "off"
        rows.append((s, hex(va), hex(alo), hex(fe) if fe else "?", on))

    for s, va, a, fe, on in sorted(rows):
        print("  %-34s data@%-10s decrypt@%-10s fn=%-10s [%s]" % (s[:34], va, a, fe, on))

    print("\n=== summary: functions that touch the crypto strings ===")
    fns = {}
    for s, va, a, fe, on in rows:
        fns.setdefault(fe, []).append(s)
    for fe, ss in fns.items():
        print("  fn %s : %s" % (fe, ", ".join(sorted(set(ss))[:8])))


if __name__ == "__main__":
    main()
