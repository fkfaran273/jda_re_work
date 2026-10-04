"""span_scan.py — static scan of the embedded libsigner code spans for
movz/movk immediate pairs that build the IV2 / DK / std-IV dwords.

Reads _LIB_SPANS straight out of signer_simple.py text (no heavy import),
scans every 4-byte aligned word for:
    movz wX,#imm16        0x52800000 | imm<<5 | X      (mov wX,#imm16)
    movk wX,#imm16,lsl#16 0x72A00000 | imm<<5 | X
and reports adjacent (movz,movk) pairs whose halves match target dwords.
"""
import base64
import re
import struct
import sys

SS = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/signer_simple.py"

SPANS_RE = re.compile(r"\((0x[0-9a-fA-F]+), (0x[0-9a-fA-F]+),\s*\n\s*\"([A-Za-z0-9+/=]+)\"")


def load_spans():
    txt = open(SS, "r", encoding="utf-8", errors="replace").read()
    i = txt.index("_LIB_SPANS = [")
    j = txt.index("]", txt.index('(0x146000', i))
    seg = txt[i:j + 1]
    spans = []
    for m in SPANS_RE.finditer(seg):
        a, b, s = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
        spans.append((a, b, base64.b64decode(s)))
    return spans


def words(spans):
    """yield (va, insn_word) for 4-byte aligned words in the spans"""
    for a, b, raw in spans:
        for off in range(0, len(raw) - 3, 4):
            w = struct.unpack_from("<I", raw, off)[0]
            yield a + off, w


def decode_movimm(w):
    """return (rd, imm16, shift) if movz/movk 32-bit imm form, else None"""
    if (w >> 23) & 0x1FF != 0b101001010:  # movz 32-bit: sf=0 opc=10 100101
        pass
    op = w >> 23
    # movz 32-bit: 0b0 10 100101 -> bits 31..23 = 0 10 100101 = 0x14A? compute:
    # 32-bit movz encoding: sf(1) opc(2)=10 100101 hw(2) imm16(16) rd(5)
    sf = (w >> 31) & 1
    opc = (w >> 29) & 3
    fixed = (w >> 23) & 0x3F
    if sf == 0 and opc == 2 and fixed == 0b100101:
        hw = (w >> 21) & 3
        imm = (w >> 5) & 0xFFFF
        rd = w & 31
        return (rd, imm, hw * 16)
    if sf == 0 and opc == 3 and fixed == 0b100101:
        hw = (w >> 21) & 3
        imm = (w >> 5) & 0xFFFF
        rd = w & 31
        return (rd, imm, hw * 16)   # movk
    return None


def main():
    spans = load_spans()
    print("spans:", [(hex(a), hex(b), len(r)) for a, b, r in spans])
    iv2 = [0xeba2c435, 0x0f4002dc, 0x9fa8dac5, 0x127035ba,
           0x7a30ed93, 0x23473054, 0xbbe3cd00, 0xf1355ea5]
    dk = [0x690f6094, 0x4dddd984, 0x7db55cd7, 0xd2d576b3,
          0x0451723f, 0xbcfa92df, 0x62b55f6f, 0xec60f2de]
    iv = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    # index all movz/movk immediates
    movs = []
    for va, w in words(spans):
        d = decode_movimm(w)
        if d:
            movs.append((va, w, d))
    print("total movz/movk imm insns:", len(movs))
    # pair up: movz imm16 (sh=0) then movk same rd (sh=16) within 16 bytes
    pairs = []
    for k in range(1, len(movs)):
        va0, w0, d0 = movs[k - 1]
        va1, w1, d1 = movs[k]
        if not (0 < va1 - va0 <= 16):
            continue
        r0, i0, s0 = d0
        r1, i1, s1 = d1
        if s0 == 0 and s1 == 16 and r0 == r1:
            pairs.append((va0, va1, r0, (i1 << 16) | i0))
    print("total movz+movk dword pairs:", len(pairs))
    for name, dwords in (("IV2", iv2), ("DK", dk), ("IVstd", iv)):
        print("---", name)
        for dv in dwords:
            hits = [(hex(a), hex(b), "w%d" % r, "%08x" % d)
                    for (a, b, r, d) in pairs if d == dv]
            print("  %08x : %s" % (dv, hits if hits else "NONE"))
    # contiguous blocks of >=6 pairs sorted by va
    blocks = []
    cur = [pairs[0]] if pairs else []
    for p in pairs[1:]:
        if p[0] - cur[-1][1] <= 0x80:
            cur.append(p)
        else:
            if len(cur) >= 6:
                blocks.append(cur)
            cur = [p]
    if len(cur) >= 6:
        blocks.append(cur)
    print("--- blocks with >=6 pairs:")
    for b in blocks:
        print("  %#x..%#x  n=%d  dwords=%s"
              % (b[0][0], b[-1][1], len(b),
                 " ".join("%08x" % d for (_, _, _, d) in b)))


if __name__ == "__main__":
    main()
