"""_sub_core_fulldata.py — full decode of the iOS core __DATA,__data string
area under every single-byte XOR key: enumerate ALL readable strings, grouped
by key, with file offsets.  Also hexdump of the claim-key neighborhood.
"""
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _sub_core_macho as macho

IOS_DEV = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins/extracted/xcframework_dyn/AdjustSigSdk.xcframework/ios-arm64/AdjustSigSdk.framework/AdjustSigSdk"

FAMILY_KEYS = [0x03, 0x05, 0x0C, 0x0F, 0x12, 0x14, 0x15, 0x1D, 0x1E, 0x2A, 0x48,
               0x4F, 0x52, 0x10, 0x17, 0x09, 0x1A]


def readable(txt, minword=5):
    return [m.group() for m in re.finditer(r"[ -~]{%d,}" % minword, txt)]


def main():
    s = macho.slices(IOS_DEV)[0]
    for seg, sec in s.sections():
        if sec["sect"] == "__data":
            fo, sz = sec["fileoff"], sec["size"]
            break
    blob = s.data[fo:fo + sz]

    print("== all decodable strings per key ==")
    seen = set()
    for k in range(256):
        dec = bytes(b ^ k for b in blob).decode("latin-1")
        for m in re.finditer(r"[a-zA-Z0-9_./ =:%<>{}()'\"-]{8,}", dec):
            txt = m.group()
            # require >= 60% alnum-ish and some lowercase word
            letters = sum(1 for c in txt if c.isalpha() or c.isdigit() or c == '_')
            if letters < 0.7 * len(txt):
                continue
            if not re.search(r"[a-z]{4}", txt):
                continue
            key = txt
            if key in seen:
                continue
            seen.add(key)
            print(f"  k={k:#04x} @{fo + m.start():#08x}: {txt!r}")

    print("\n== hexdump 0x1d6080..0x1d6200 (claim-key blocks) ==")
    for base in range(0x1d6080, 0x1d6200, 16):
        row = s.data[base:base + 16]
        print(f"  {base:#08x}  {row.hex(' ')}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")

    print("\n== hexdump 0x1d6a20..0x1d6b50 (idfv/pp_version_short/secret_id) ==")
    for base in range(0x1d6a20, min(0x1d6b50, fo + sz), 16):
        row = s.data[base:base + 16]
        print(f"  {base:#08x}  {row.hex(' ')}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")


if __name__ == "__main__":
    main()
