"""hunt_iv2k.py — HOW the FinEx VM (libsigner.so / adj9) generates IV2 and DK.

VERDICT (proven at instruction level, see IV2K_DERIVED.md):
    IV2 and DK are NOT computed from any input.  They are CONSTANTS EMBEDDED
    IN THE VM BYTECODE as movz/movk immediate pairs:

      * IV2 (the custom SHA-256 chaining IV) is stored WHITENED: each of its
        8 dwords is the literal immediate XOR 0xCCCCCCCC.  At runtime an
        unrolled literal block pushes the whitened dwords through the LIFO
        value queue, stages them in MAIN scratch, copies them to the SHA-256
        state slot MAIN[65..72], and de-whitens them IN PLACE with an
        `eor w2, w0, w21` loop whose mask literal is `mov w2, #0xCCCCCCCC`
        (encoding 0x3202e7e2, pc 0x1248a8 in the r0 sample run).

      * DK (the digest MAC key) is stored PLAIN: 8 dwords of mov/movk
        immediates, pushed unmasked.

    Corroborating structure: the standard SHA-256 IV is stored the same way
    (XOR 0xCCCCCCCC, two program copies) and the 64 SHA-256 round constants
    are stored XOR 0xAAAAAAAA (two copies).  Those two FIPS-anchored blocks
    validate the extractor end to end; IV2 is then "the remaining unique
    XOR-0xCC-masked block" and DK "the remaining unique plain block".

    This explains the CRITICAL FACT exactly: no 8-byte window of IV2/DK can
    appear in the file because each dword lives as two 16-bit halves inside
    two separate instruction encodings (and, for IV2, additionally XORed).

derive_iv2() / derive_k() below are stdlib-only: they parse the embedded
code spans (_LIB_SPANS) straight out of signer_simple.py, decode the
immediates with bit twiddling (no capstone), and rebuild both constants.

Run:  python hunt_iv2k.py     -> verifies 32/32 + end-to-end blob checks
"""
import base64
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALG = os.path.dirname(HERE)
REV = os.path.dirname(ALG)
SIGNER_SIMPLE = os.path.normpath(os.path.join(
    ALG, "..", "..", "..", "adj9sign", "signer_simple.py"))

# ---------------------------------------------------------------- spans ----
_SPANS_RE = re.compile(r"\((0x[0-9a-fA-F]+), (0x[0-9a-fA-F]+),\s*\n\s*\"([A-Za-z0-9+/=]+)\"")


def load_spans(path=SIGNER_SIMPLE):
    """[(start_va, end_va, bytes)] — read-only parse of _LIB_SPANS."""
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    i = txt.index("_LIB_SPANS = [")
    j = txt.index("]", txt.index("(0x146000", i))
    spans = []
    for m in _SPANS_RE.finditer(txt[i:j + 1]):
        spans.append((int(m.group(1), 16), int(m.group(2), 16),
                      base64.b64decode(m.group(3))))
    return spans


def word_at(spans, va):
    for a, b, raw in spans:
        if a <= va < b and va + 4 <= b:
            return struct.unpack_from("<I", raw, va - a)[0]
    return None


# ------------------------------------------------- ARM64 imm decoding ----
def decode_mov_imm32(w):
    """MOVZ/MOVK 32-bit immediate form -> (rd, imm16, shift) or None."""
    sf = (w >> 31) & 1
    opc = (w >> 29) & 3
    fixed = (w >> 23) & 0x3F
    if sf != 0 or fixed != 0b100101 or opc not in (2, 3):
        return None
    hw = (w >> 21) & 3
    return (w & 31, (w >> 5) & 0xFFFF, hw * 16)   # opc2=movz, 3=movk


def _ror(x, n, width):
    n %= width
    return ((x >> n) | (x << (width - n))) & ((1 << width) - 1)


def decode_orr_imm(w):
    """ORR (immediate) with Rn=xzr (the `mov wX,#imm` bitmask alias)
    -> (rd, value) or None.  sf=0 only (32-bit)."""
    if (w >> 31) & 1:
        return None
    if ((w >> 29) & 3) != 1 or ((w >> 23) & 0x3F) != 0b100100:
        return None
    if ((w >> 5) & 31) != 31:
        return None
    rd = w & 31
    n = (w >> 22) & 1
    immr = (w >> 16) & 0x3F
    imms = (w >> 10) & 0x3F
    v = (n << 6) | ((~imms) & 0x3F)
    if v == 0:
        return None
    b = v.bit_length() - 1          # len = HighestSetBit(N:NOT(imms))
    esize = 1 << b
    levels = (1 << b) - 1
    s = imms & levels
    r = immr & levels
    if s == levels and esize > 1:
        return None
    welem = (1 << (s + 1)) - 1      # run of S+1 ones
    elem = _ror(welem, r, esize) if esize > 1 else 1
    val = 0
    for k in range(32 // esize):
        val |= elem << (k * esize)
    return (rd, val)


# ------------------------------------------------- mov/movk pair blocks ----
def mov_movk_dwords(spans):
    """All (pc, rd, dword) built by movz #imm16 + movk #imm16,lsl#16 within
    16 bytes of each other (same rd)."""
    movs = []
    for a, b, raw in spans:
        for off in range(0, len(raw) - 3, 4):
            d = decode_mov_imm32(struct.unpack_from("<I", raw, off)[0])
            if d:
                movs.append((a + off, d))
    pairs = []
    for k in range(1, len(movs)):
        va0, (r0, i0, s0) = movs[k - 1]
        va1, (r1, i1, s1) = movs[k]
        if 0 < va1 - va0 <= 16 and s0 == 0 and s1 == 16 and r0 == r1:
            pairs.append((va0, va1, r0, (i1 << 16) | i0))
    return pairs


def group_blocks(pairs, gap=0x80, min_pairs=6):
    """Contiguous runs of pairs -> [(pc_lo, pc_hi, [dwords])]"""
    blocks, cur = [], []
    for p in pairs:
        if cur and p[0] - cur[-1][1] > gap:
            if len(cur) >= min_pairs:
                blocks.append((cur[0][0], cur[-1][1], [d for *_, d in cur]))
            cur = []
        cur.append(p)
    if len(cur) >= min_pairs:
        blocks.append((cur[0][0], cur[-1][1], [d for *_, d in cur]))
    return blocks


# ------------------------------------------------------- FIPS-180-4 ----
SHA256_ROUND_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2]
SHA256_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]


# ------------------------------------------------------- derivation ----
def _extract(spans):
    """-> dict with block facts used by derive_iv2/derive_k."""
    pairs = mov_movk_dwords(spans)
    blocks = group_blocks(pairs)
    facts = {"pairs": pairs, "blocks": blocks, "masks": [], "anchors": []}
    # mask literal sites (mov wX,#0xCCCCCCCC / #0xAAAAAAAA)
    for a, b, raw in spans:
        for off in range(0, len(raw) - 3, 4):
            va = a + off
            d = decode_orr_imm(struct.unpack_from("<I", raw, off)[0])
            if d and d[1] in (0xCCCCCCCC, 0xAAAAAAAA):
                facts["masks"].append((va, d[1]))
    # FIPS anchors
    ok = []
    for lo, hi, dw in blocks:
        if len(dw) == 64 and [x ^ 0xAAAAAAAA for x in dw] == SHA256_ROUND_K:
            ok.append(("round-constants ^0xAA", lo, hi))
        if len(dw) == 8 and [x ^ 0xCCCCCCCC for x in dw] == SHA256_IV:
            ok.append(("standard-IV ^0xCC", lo, hi))
    facts["anchors"] = ok
    return facts


def _dwords_be(dwords):
    return b"".join(struct.pack(">I", d) for d in dwords)


def derive_iv2(spans=None, facts=None):
    """IV2 = the lowest-address 8-dword mov/movk block, each dword
    de-whitened with XOR 0xCCCCCCCC -> 32 bytes."""
    if spans is None:
        spans = load_spans()
    if facts is None:
        facts = _extract(spans)
    e8 = [(lo, hi, dw) for (lo, hi, dw) in facts["blocks"] if len(dw) == 8]
    assert len(e8) == 4, "expected 4 eight-dword mov/movk blocks, got %d" % len(e8)
    e8.sort(key=lambda t: t[0])
    lo_iv2, lo_dk, lo_iv_a, lo_iv_b = [t[0] for t in e8]
    # structure: block1=IV2^cc, block2=DK plain, blocks 3&4 = std IV ^cc (dup)
    assert e8[2][2] == e8[3][2], "std-IV block should appear twice"
    assert [x ^ 0xCCCCCCCC for x in e8[2][2]] == SHA256_IV
    assert e8[0][2] != e8[2][2]
    iv2 = bytes(b ^ 0xCC for b in _dwords_be(e8[0][2]))
    dk = _dwords_be(e8[1][2])
    return iv2, dk, {"iv2_block": (e8[0][0], e8[0][1]),
                     "dk_block": (e8[1][0], e8[1][1]),
                     "iv_blocks": (e8[2][0], e8[2][1], e8[3][0], e8[3][1])}


def derive_k(spans=None, facts=None):
    """DK = the second 8-dword mov/movk block (plain immediates) -> 32 B."""
    return derive_iv2(spans, facts)[1]


# ------------------------------------------------------- verification ----
def verify_against_pure_sign(iv2, dk):
    sys.path.insert(0, os.path.join(ALG, "pure_signer"))
    import pure_sign
    r1 = (iv2 == pure_sign.IV2)
    r2 = (dk == pure_sign.DK)
    return r1, r2, pure_sign


def verify_end_to_end(pure_sign, iv2, dk, n=3):
    """Rebuild genuine blobs with the DERIVED constants patched in."""
    pure_sign.IV2 = iv2
    pure_sign.DK = dk
    pure_sign.K_IPAD = bytes(a ^ b for a, b in zip(dk, pure_sign.IPAD))
    pure_sign.K_OPAD = bytes(a ^ b for a, b in zip(dk, pure_sign.OPAD))
    vecs = json.load(open(os.path.join(ALG, "pure_signer", "_vectors_tmp.json")))
    good = 0
    for e in vecs[:n]:
        blob = pure_sign.sign_pure(e["second"], e["S"], e["map"], e["kind"],
                                   d9_hex=e["d9_hex"], head=tuple(e["head"]))
        good += int(blob == bytes.fromhex(e["blob_hex"]))
    return good, min(n, len(vecs))


def verify_runtime_trace(iv2, dk):
    """Cross-check the r0 emit trace: the staging events must carry exactly
    the derived constants (and their 0xCC images)."""
    p = os.path.join(ALG, "digest_law", "digest_emits.json")
    if not os.path.exists(p):
        return None
    EM = json.load(open(p))
    MAIN = 0x5450001000
    def grab(step_lo, step_hi, n_lo, n_hi):
        d = {}
        for (st, sva, top, n, v, idx) in EM:
            if sva == MAIN and n_lo <= n <= n_hi and step_lo <= st <= step_hi:
                d[n] = v
        return [d[i] for i in sorted(d)]
    iv2w = list(struct.unpack(">8I", iv2))
    dkw = list(struct.unpack(">8I", dk))
    myv_w = [x ^ 0xCCCCCCCC for x in iv2w]
    out = {}
    # IV2 staged forward into MAIN[65..72] at ~558818 (after eor 0xCC)
    got = grab(558700, 559500, 65, 72)
    out["iv2_emits(MAIN[65..72])"] = (got == iv2w)
    # whitened source copied to MAIN[65..72] at ~558605
    got = grab(558550, 558750, 65, 72)
    out["iv2^cc_copy(MAIN[65..72])"] = (got == myv_w)
    # whitened literals staged reverse into MAIN[612..619] at ~540036
    got = grab(539900, 540200, 612, 619)
    out["iv2^cc_literal(MAIN[612..619])"] = (got == myv_w)
    # DK staged reverse into MAIN[612..619] at ~8205502
    got = grab(8204900, 8205700, 612, 619)
    out["dk_emits(MAIN[612..619])"] = (got == dkw)
    return out


def main():
    spans = load_spans()
    print("== embedded code spans ==")
    for a, b, raw in spans:
        print("  %#x..%#x  (%d B)" % (a, b, len(raw)))

    facts = _extract(spans)
    print("\n== movz+movk dword-pair blocks (>=6 pairs) ==")
    for lo, hi, dw in facts["blocks"]:
        print("  %#x..%#x  n=%-3d %s" % (lo, hi, len(dw),
              " ".join("%08x" % d for d in dw[:8]) + (" ..." if len(dw) > 8 else "")))
    print("\n== mask literals (mov wX,#imm via ORR-bitmask, Rn=xzr) ==")
    for va, val in facts["masks"]:
        print("  %#x: mov w?,#%#x" % (va, val))
    print("\n== FIPS-180-4 anchors (extractor self-check) ==")
    for name, lo, hi in facts["anchors"]:
        print("  OK  %s  at %#x..%#x" % (name, lo, hi))

    iv2, dk, locs = derive_iv2(spans, facts)
    print("\n== derived constants ==")
    print("  IV2 block  %#x..%#x" % locs["iv2_block"])
    print("  DK  block  %#x..%#x" % locs["dk_block"])
    print("  IV2 = %s" % iv2.hex())
    print("  DK  = %s" % dk.hex())

    print("\n== verification vs pure_sign.py recorded constants ==")
    r1, r2, ps = verify_against_pure_sign(iv2, dk)
    print("  IV2 32/32: %s   DK 32/32: %s" % (r1, r2))

    rt = verify_runtime_trace(iv2, dk)
    if rt:
        print("\n== runtime emit-trace cross-check (r0 sample run) ==")
        for k, v in rt.items():
            print("  %-36s %s" % (k, "OK" if v else "FAIL"))

    print("\n== end-to-end genuine-blob rebuild with derived constants ==")
    try:
        good, tot = verify_end_to_end(ps, iv2, dk)
        print("  %d/%d blobs byte-exact" % (good, tot))
    except Exception as ex:
        print("  skipped:", ex)

    return 0 if (r1 and r2 and all(rt.values())) else 1


if __name__ == "__main__":
    sys.exit(main())
