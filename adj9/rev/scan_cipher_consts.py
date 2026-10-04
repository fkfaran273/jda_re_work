"""Wall A: scan libsigner.so for STREAM-CIPHER / ARX / checksum constants
(mov/movk immediates in .text + aligned dwords in .rodata/.data).
The prior scan_consts.py only covered hash families (SHA/MD5); this covers
the families a table-free keystream would actually use.
"""
import os, sys
from collections import defaultdict
import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
from decryptors import LIB

def sm4_ck():
    out = []
    for i in range(32):
        b = [(4 * i + 4 * k + k) & 0xff for k in range(4)]  # placeholder, replaced below
        out.append(0)
    # CK_j = (j*4+0, j*4+1+... real derivation: bytes (4j, 4j+7...)...
    # canonical list:
    out = [0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,
           0xa8afb6bd,0xc4cbd2d9,0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
           0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,0xc0c7ced5,0xdce3eaf1,
           0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
           0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,
           0x484f565d,0x646b7279]
    return out

GROUPS = {
    "CHACHA_SIGMA": [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574],
    "TEA":          [0x9E3779B9, 0xC6EF3720],          # delta, delta*32
    "SM4_FK":       [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC],
    "SM4_CK":       sm4_ck(),
    "CRC32":        [0xEDB88320, 0x04C11DB7],
    "MURMUR3":      [0xCC9E2D51, 0x1B873593, 0xE6546B64, 0x85EBCA6B, 0xC2B2AE35],
    "XXHASH":       [0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1],
    "FNV":          [0x01000193, 0x811C9DC5, 0x010001A1],
    "BLOWFISH_PI":  [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822],
    "SHA1_K":       [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6],
    "MD5_H":        [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
    "SPECK/SIMON":  [0x0F1E2D3C],  # speck z0 start (weak signal)
}

def scan():
    e = ELF(LIB)

    # --- dword scan over data sections (aligned + unaligned record) ---
    print("=== dword scan of .rodata / .data / .data.rel.ro ===")
    want = {v: g for g, vs in GROUPS.items() for v in vs}
    for sec in (".rodata", ".data.rel.ro", ".data"):
        try:
            addr, size = e.byname[sec]["addr"], e.byname[sec]["size"]
            off = e.vaddr_to_off(addr)
        except Exception:
            continue
        blob = e.data[off:off + size]
        for i in range(0, len(blob) - 4):
            v = int.from_bytes(blob[i:i + 4], "little")
            if v in want:
                print(f"  {want[v]:12s} 0x{v:08x} @ {sec}+0x{i} (va 0x{addr + i:x})")

    # --- mov/movk immediate scan over .text ---
    print("\n=== mov/movk immediate scan of .text ===")
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    t = e.byname[".text"]
    off0 = e.vaddr_to_off(t["addr"])
    code = e.data[off0:off0 + t["size"]]
    halfmap = defaultdict(list)
    for g, vals in GROUPS.items():
        for v in set(vals):
            halfmap[v & 0xFFFF].append((g, v, 0))
            halfmap[(v >> 16) & 0xFFFF].append((g, v, 16))
    hits = defaultdict(list)
    for insn in md.disasm(code, t["addr"]):
        if insn.mnemonic not in ("mov", "movz", "movk", "orr", "eon"):
            continue
        for op in insn.operands:
            if op.type != capstone.arm64.ARM64_OP_IMM:
                continue
            imm = op.imm & 0xFFFF
            shift = op.shift.value if op.shift.type else 0
            for (g, v, want_shift) in halfmap.get(imm, ()):
                if shift == want_shift:
                    hits[(g, v)].append(insn.address)
    for g in GROUPS:
        gg = {v: a for (gr, v), a in hits.items() if gr == g}
        if not gg:
            print(f"  {g:12s} : 0 hits")
            continue
        print(f"  {g:12s} : {len(gg)}/{len(set(GROUPS[g]))} constants")
        for v, a in sorted(gg.items(), key=lambda x: -len(x[1]))[:6]:
            print(f"      0x{v:08x}  {len(a):2d} site(s)  e.g. 0x{a[0]:x}")

    # --- dump .rodata head (the two 16B constants live at +0xc0/+0xe0) ---
    print("\n=== .rodata[0x00..0x180] as dwords ===")
    addr = e.byname[".rodata"]["addr"]
    blob = e.data[e.vaddr_to_off(addr):e.vaddr_to_off(addr) + 0x180]
    for r in range(0, len(blob), 16):
        ws = " ".join(f"{int.from_bytes(blob[r + k:r + k + 4], 'little'):08x}" for k in (0, 4, 8, 12))
        print(f"  +0x{r:03x} (va 0x{addr + r:x}): {ws}")

if __name__ == "__main__":
    scan()
