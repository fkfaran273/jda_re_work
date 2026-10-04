"""_sub_claims3_strcrack.py — crack the remaining undecoded strings of the
iOS core's XOR-obfuscated string pool (double-XOR family; the single-key
pass left garbage like 'SWQSP', 'P^U^QSPWPPP', 'knin', '4cbfh', 'K_DIL').

Attack: single-byte XOR, double-byte XOR (k2 sweep), case-flip, add/sub,
with printable/lowercase scoring + crib confirmation against the known
vocabulary (adj9, ios, idfa, nonce, secret, ...).
"""
import json
import os
import string

HERE = os.path.dirname(os.path.abspath(__file__))
PRINT = set(bytes(string.printable[:-5], "ascii"))
COMMON = [b"adj", b"ios", b"idfa", b"idfv", b"udid", b"uuid", b"nonce",
          b"secret", b"sandbox", b"production", b"apple", b"root",
          b"cert", b"frida", b"gadget", b"os_", b"bundle", b"version",
          b"environment", b"signature", b"key", b"id", b"sign", b"receipt",
          b"pkcs", b"pkcs7", b"store", b"sku", b"quantity", b"transaction"]


def score(b):
    if not b:
        return -1
    pr = sum(1 for c in b if c in PRINT) / len(b)
    lo = sum(1 for c in b if 0x61 <= c <= 0x7A) / len(b)
    dg = sum(1 for c in b if 0x30 <= c <= 0x39) / len(b)
    s = pr * 2 + lo + dg * 0.5
    for c in COMMON:
        if c in b.lower():
            s += 3
    for bad in (b"\x00",):
        if bad in b:
            s -= 5
    return s


def candidates(enc):
    out = []
    n = len(enc)
    # single xor
    for k in range(256):
        out.append(bytes(c ^ k for c in enc))
    # double xor: k1 from printable range, k2 sweep (too big) -> k1 = any,
    # k2 = small set including 0x20 (case), 0x55, 0xCC, 0xAA, 0xEF, 0x5A..
    K2S = [0x00, 0x20, 0x55, 0xAA, 0xCC, 0xEF, 0x5A, 0x33, 0x3C, 0x0F, 0xF0]
    for k1 in range(256):
        base = bytes(c ^ k1 for c in enc)
        for k2 in K2S:
            if k2:
                out.append(bytes(c ^ k2 for c in base))
        # add/sub after xor
        for d in (1, 0x10, 0x20, 0x1F):
            out.append(bytes((c + d) & 0xFF for c in base))
            out.append(bytes((c - d) & 0xFF for c in base))
    # case flip of every single-xor
    for k in range(256):
        out.append(bytes((c ^ k) ^ 0x20 for c in enc))
    # dedup
    seen = set()
    uniq = []
    for b in out:
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return uniq


def best(enc, top=3):
    cands = candidates(enc)
    cands.sort(key=score, reverse=True)
    return cands[:top]


def main():
    # undecoded entries: from _sub_core_order_strings.json (key, enc text)
    data = json.load(open(os.path.join(HERE, "_sub_core_order_strings.json")))
    report = {}
    for addr, k, s in data:
        if not s or all(ch in string.ascii_letters + "_-. " for ch in s) \
                and s.lower() == s or True:
            pass
        enc = bytes(ord(c) & 0xFF for c in s)
        # only run on entries that do NOT look like clean words already
        clean = all((0x61 <= ord(c) <= 0x7A) or (0x30 <= ord(c) <= 0x39)
                    or c in "_-./ " for c in s)
        has_upper = any(c.isupper() for c in s) or any(ord(c) > 127
                                                       for c in s)
        if clean and not has_upper:
            continue
        if len(s) < 4 or len(s) > 40:
            continue
        top = best(enc)
        b = top[0]
        if score(b) > 3.5:
            report[str(addr)] = {"enc": s, "k": k, "best": [t.decode("latin1", "replace") for t in top]}
    for a, v in sorted(report.items(), key=lambda x: int(x[0])):
        print(a, "k=%3d" % v["k"], repr(v["enc"]), "->",
              " | ".join(repr(t) for t in v["best"]))
    with open(os.path.join(HERE, "_sub_claims3_strcrack_out.json"), "w") as f:
        json.dump(report, f, indent=1)


if __name__ == "__main__":
    main()
