"""spn_consthunt.py — static hunt in libsigner.so:
1. locate SBOX candidates (AES / adj9 / inverse) in the image
2. find adrp+add references to the KB page (0xd2000/0xd6000)
3. find byte-table lookup code (ldrb with scaled index) near those refs

    python spn_consthunt.py
"""
import json
import os
import struct
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
SO = os.path.join(WORK, "bins", "adjust-android-signature-3.62", "jni",
                  "arm64-v8a", "libsigner.so")
data = open(SO, "rb").read()
print("so size", len(data))

# --- 1. SBOX candidates ---
sys.path.insert(0, os.path.join(WORK, "..", "adj9_ios"))
try:
    import adj9ios_pure as sg9
    SBOX9 = bytes(sg9.SBOX)
except Exception as e:
    SBOX9 = None
    print("adj9 import failed:", e)

AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
cands = {"aes": AES_SBOX}
if SBOX9:
    cands["adj9"] = SBOX9
    cands["aes_inv"] = bytes(256)  # placeholder compute below
INV = [0] * 256
for i, v in enumerate(AES_SBOX):
    INV[v] = i
cands["aes_inv"] = bytes(INV)
if SBOX9:
    INV9 = [0] * 256
    for i, v in enumerate(SBOX9):
        INV9[v] = i
    cands["adj9_inv"] = bytes(INV9)

for nm, sb in cands.items():
    if len(sb) != 256:
        continue
    idx = data.find(sb)
    hits = []
    while idx != -1 and len(hits) < 8:
        hits.append(hex(idx))
        idx = data.find(sb, idx + 1)
    print("SBOX %s found at file offsets: %s" % (nm, hits))
    # first-16 match (table may be byte-swapped etc.)
    i16 = data.find(sb[:16])
    print("   first16 at:", [hex(i16)] if i16 >= 0 else "none")

# --- 2. adrp+add to KB page 0xd2000 / 0xd6000 and 0xba000 (SHA IV) ---
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
refs = {}
# scan .text for adrp: encoding bits; simpler: capstone-scan whole text in
# 4-byte steps only when opcode matches adrp pattern is slow; instead scan
# for adrp immediates by brute disasm of every 4-byte word as adrp is
# expensive. Use heuristic: adrp Xn, #imm pages 0xd2000/0xd6000: search
# raw encoding. adrp: op=1ii10000; we brute-force all 4-byte words and decode.
targets = {0xd2000: "KB_d20a0_page", 0xd6000: "KB_d6c18_page",
           0xba000: "shaIV_ba958_page", 0xd7000: "shaIV2_d7abc_page"}
n = len(data) - 8
found = []
for off in range(0, 0x117000, 4):
    w = struct.unpack_from("<I", data, off)[0]
    if (w & 0x9F000000) == 0x90000000:            # adrp
        rd = w & 31
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= 1 << 33
        page = (off & ~0xFFF) + imm
        if page in targets:
            found.append((off, rd, page))
print("adrp refs to target pages:", len(found))
by_page = {}
for off, rd, page in found:
    by_page.setdefault(page, []).append((off, rd))
for page, lst in by_page.items():
    print("  page %#x: %d refs, first %s" %
          (page, len(lst), [(hex(o), "x%d" % r) for o, r in lst[:6]]))
