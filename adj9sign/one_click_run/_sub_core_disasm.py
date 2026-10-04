"""_sub_core_disasm.py — capstone-lite disassembly of the two iOS functions
that reference the claim-key strings in ascending order (candidates for the
claims composition), plus decode of remaining obfuscated strings.
"""
import os
import struct
import sys

import capstone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _sub_core_macho as macho

IOS_DEV = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins/extracted/xcframework_dyn/AdjustSigSdk.xcframework/ios-arm64/AdjustSigSdk.framework/AdjustSigSdk"

KEY_STRINGS = {
    0x1d6048: "environment", 0x1d6060: "?060", 0x1d6087: "?087",
    0x1d6090: "activity_kind", 0x1d60a0: "client_sdk",
    0x1d60b0: "adj_signing_id", 0x1d60c0: "signature",
    0x1d60d0: "headers_id", 0x1d60e0: "native_version",
    0x1d60f0: "algorithm", 0x1d6100: "adj_verification",
    0x1d6118: "authorization", 0x1d6130: "network_payload",
    0x1d6140: "endpoint", 0x1d6150: "?150", 0x1d6180: "log:Signing-all-the-parameters-begin",
    0x1d6a32: "idfv", 0x1d6a38: "app_version",
    0x1d6a50: "app_version_short", 0x1d6aa8: "secret_id",
    0x1d6ab0: "?ab0", 0x1d6ad0: "frida-gadget", 0x1d6ae0: "?ae0",
    0x1d6a1f: "?a1f", 0x1d6a23: "?a23", 0x1d6a28: "?a28",
    0x1d6a68: "?a68", 0x1d6a70: "?a70", 0x1d6a98: "?a98",
    0x1d6a8b: "?a8b", 0x1d6a91: "?a91",
}


def disasm_window(md, d, start, end, label):
    print(f"\n---- {label}: {start:#x}..{end:#x} ----")
    code = d[start:end]
    for ins in md.disasm(code, start):
        note = ""
        # adrp+add target annotation
        if ins.mnemonic == "adrp":
            pass
        print(f"  {ins.address:#08x}  {ins.mnemonic:<8} {ins.op_str}")


def main():
    s = macho.slices(IOS_DEV)[0]
    d = s.data
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    disasm_window(md, d, 0x6cf90, 0x6d1a0, "key-order function A (0x6cf90)")
    disasm_window(md, d, 0x6ba10, 0x6baf0, "key-order function B head (0x6ba10)")

    # decode remaining strings with full brute force + word scoring
    print("\n== remaining string decodes ==")
    cands = [0x1d6060, 0x1d6087, 0x1d6150, 0x1d6548, 0x1d6556, 0x1d6560,
             0x1d6a1f, 0x1d6a23, 0x1d6a28, 0x1d6a68, 0x1d6a70, 0x1d6a8b,
             0x1d6a91, 0x1d6a98, 0x1d6ab0, 0x1d6ac0, 0x1d6ac3, 0x1d6ae0,
             0x1d5970, 0x1d59b8, 0x1d6560]
    import re
    for off in cands:
        j = off
        raw = bytearray()
        while j < len(d) and d[j] != 0 and j - off < 128:
            raw.append(d[j]); j += 1
        scored = []
        for k in range(256):
            dec = bytes(c ^ k for c in raw)
            try:
                t = dec.decode("ascii")
            except UnicodeDecodeError:
                continue
            lw = sum(1 for c in t if c.islower() or c in "_0123456789 ")
            if lw >= 0.55 * len(t):
                scored.append((lw, k, t))
        scored.sort(reverse=True)
        print(f"   {off:#08x} raw={bytes(raw).hex()}")
        for sc, k, t in scored[:3]:
            print(f"        k={k:#04x} {t!r}")


if __name__ == "__main__":
    main()
