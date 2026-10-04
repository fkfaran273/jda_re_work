"""_sub_core_refs.py — find __text code sites referencing the claim-key
strings (adrp+add pair resolution) to establish key usage order; decode the
leftover obfuscated families; dump the frida-gadget neighborhood.
"""
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _sub_core_macho as macho

IOS_DEV = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins/extracted/xcframework_dyn/AdjustSigSdk.xcframework/ios-arm64/AdjustSigSdk.framework/AdjustSigSdk"


def adrp_add_sites(d, text_off, text_size, want_lo, want_hi):
    """Decode adrp+add pairs; return [(code_off, target_addr, rd)]."""
    n = (text_size) // 4
    W = struct.unpack_from("<%dI" % n, d, text_off)
    out = []
    openadrp = {}
    for i in range(n):
        w = W[i]
        # ADRP: op=1, bits 28-24 = 10000
        if (w & 0x9F000000) == 0x90000000:
            rd = w & 0x1F
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= (1 << 21)
            page = ((i * 4 + text_off) & ~0xFFF) + (imm << 12)
            # note: PC-relative from the instruction's own page
            openadrp[rd] = (page, i)
            continue
        # ADD (immediate) 64-bit: sf=1 op=0 100010 sh=0 imm12 Rn Rd
        if (w & 0xFF800000) == 0x91000000:
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if rn in openadrp and rn == rd:
                page, pi = openadrp[rn]
                tgt = page + imm12
                if want_lo <= tgt < want_hi:
                    out.append((text_off + i * 4, tgt, rd))
                del openadrp[rn]
            continue
        # any write to rd invalidates
        rd = w & 0x1F
        if rd in openadrp and (w >> 28) not in (0x9, 0x8, 0xB, 0xA):
            openadrp.pop(rd, None)
    return out


def main():
    s = macho.slices(IOS_DEV)[0]
    d = s.data
    # text section
    for seg, sec in s.sections():
        if sec["sect"] == "__text":
            text_off, text_size, text_addr = sec["fileoff"], sec["size"], sec["addr"]
            break

    # leftover-family decodes
    print("== leftover family decodes ==")
    fam = {
        0x1d5520: (0x43, 0x40), 0x1d5540: (0x54, 0x40), 0x1d5970: (0x1a, 0x2C),
        0x1d59b8: (0x71, 0x0A), 0x1d6a68: (0x66, 0x40), 0x1d6a8b: (0x6c, 0x40),
        0x1d6a91: (0x64, 0x40), 0x1d6a98: (0xd7, 0x2C), 0x1d6150: (0xb3, 0x2C),
        0x1d61b0: (0xa9, 0x2C), 0x1d6548: (0x93, 0x2C),
    }
    for off, (k1, extra) in fam.items():
        raw = []
        j = off
        while d[j] != 0:
            raw.append(d[j])
            j += 1
        k = k1 ^ extra
        dec = bytes(c ^ k for c in raw).decode("latin-1")
        print(f"   {off:#08x} k={k:#04x} {dec!r}")

    # all simulator-family via k^0x06 etc. quick
    for off, k in [(0x1d61e0, 0x15), (0x1d6510, 0x93), (0x1d6530, 0x93)]:
        j = off
        raw = b""
        while d[j] != 0:
            raw += bytes([d[j]]); j += 1
        print(f"   {off:#08x} k={k:#04x} {raw.decode('latin-1')!r}")

    # frida-gadget neighborhood
    print("\n== frida-gadget neighborhood (0x1d6ab0..0x1d6b50) ==")
    for off in range(0x1d6ab0, 0x1d6b50, 16):
        row = d[off:off + 16]
        print(f"   {off:#08x}  {row.hex(' ')}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")

    # code references into claim-key pool 0x1d6040..0x1d6b50
    refs = adrp_add_sites(d, text_off, text_size, 0x1d6040, 0x1d6b50)
    print(f"\n== __text adrp+add refs into string pool: {len(refs)} ==")
    by_str = {}
    for code_off, tgt, rd in refs:
        by_str.setdefault(tgt, []).append(code_off)
    for tgt in sorted(by_str):
        sites = ", ".join(hex(c) for c in by_str[tgt][:6])
        print(f"   {tgt:#08x} <- {sites}")

    # order of references within __text for the claim keys
    seq = sorted((c, t) for t, lst in by_str.items() for c in lst)
    print("\n== reference sequence by code address ==")
    for c, t in seq:
        print(f"   code {c:#09x} -> {t:#08x}")

    with open(os.path.join(HERE, "_sub_core_refs_out.json"), "w") as f:
        json.dump({"refs": [[c, t] for c, t in seq]}, f, indent=1)


if __name__ == "__main__":
    main()
