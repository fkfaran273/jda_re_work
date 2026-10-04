"""_sub_core_clusters.py — cluster all adrp+add references to the iOS core
string pool by function (gap>0x2000 => new cluster) and print the ordered
key sequences; final decodes of remaining strings.
"""
import os
import struct
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _sub_core_macho as macho
from _sub_core_refs import adrp_add_sites

IOS_DEV = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins/extracted/xcframework_dyn/AdjustSigSdk.xcframework/ios-arm64/AdjustSigSdk.framework/AdjustSigSdk"

NAMES = {
    0x1d6048: "environment", 0x1d6060: "LOG:SDKv5-Signing-begin",
    0x1d6087: "log-flag", 0x1d6090: "activity_kind", 0x1d60a0: "client_sdk",
    0x1d60b0: "adj_signing_id", 0x1d60c0: "signature",
    0x1d60d0: "headers_id", 0x1d60e0: "native_version",
    0x1d60f0: "algorithm", 0x1d6100: "adj_verification",
    0x1d6118: "authorization", 0x1d6130: "network_payload",
    0x1d6140: "endpoint", 0x1d6150: "LOG:Signing-end",
    0x1d6180: "LOG:Signing-begin2", 0x1d61b0: "LOG:?1b0",
    0x1d64e7: "?4e7", 0x1d6510: "ADJRequestHandler",
    0x1d6530: "signWithSigPlugin", 0x1d6548: "sendPackageBy",
    0x1d6556: "ios", 0x1d6560: "?560",
    0x1d6a1f: "?a1f", 0x1d6a23: "?a23", 0x1d6a28: "bundle_id",
    0x1d6a32: "idfv", 0x1d6a38: "app_version",
    0x1d6a50: "app_version_short", 0x1d6a68: "os_name",
    0x1d6a70: "?a70", 0x1d6a8b: "?a8b", 0x1d6a91: "?a91",
    0x1d6a98: "?a98", 0x1d6aa8: "secret_id",
    0x1d6ab8: "VALUE:1500000", 0x1d6ac3: "VALUE:adj9",
    0x1d6ad0: "frida-gadget", 0x1d6ae0: "AgentController",
}


def main():
    s = macho.slices(IOS_DEV)[0]
    d = s.data
    for seg, sec in s.sections():
        if sec["sect"] == "__text":
            text_off, text_size = sec["fileoff"], sec["size"]
            break
    refs = adrp_add_sites(d, text_off, text_size, 0x1d5340, 0x1d6b50)
    # keep only refs we can name (claim pool) or log strings
    named = [(c, t) for c, t, _rd in refs if t in NAMES]
    # cluster by 0x1000 gap
    clusters = []
    cur = [named[0]]
    for prev, item in zip(named, named[1:]):
        if item[0] - prev[0] > 0x1000:
            clusters.append(cur)
            cur = []
        cur.append(item)
    clusters.append(cur)
    print("== per-cluster ordered key references ==")
    for cl in clusters:
        if len(cl) < 3:
            continue
        print(f"  cluster {cl[0][0]:#x}..{cl[-1][0]:#x} ({len(cl)} refs):")
        seq = [NAMES.get(t, hex(t)) for _, t in cl]
        # collapse consecutive dups
        out = []
        for x in seq:
            if not out or out[-1] != x:
                out.append(x)
        print("    " + " -> ".join(out))

    # final decodes
    print("\n== final decodes ==")
    def dec(off, k, n=64):
        j = off
        raw = bytearray()
        while j < len(d) and d[j] != 0 and len(raw) < n:
            raw.append(d[j]); j += 1
        return bytes(c ^ k for c in raw)

    for off, k in [(0x1d59b8, 0x44), (0x1d5a00, 0xD6), (0x1d6a98, 0xFB),
                   (0x1d6a8b, 0x2C), (0x1d6a91, 0x24), (0x1d6a70, 0x52)]:
        print(f"   {off:#x} k={k:#x}: {dec(off, k)!r}")
    # /dev/urandom brute
    for k in range(256):
        t = dec(0x1d59b8, k)
        try:
            ts = t.decode('ascii')
        except Exception:
            continue
        if 'rando' in ts or 'dev/' in ts:
            print(f"   0x1d59b8 k={k:#x}: {ts!r}")
    # 0x1d6a98 brute
    best = []
    for k in range(256):
        t = dec(0x1d6a98, k)
        try:
            ts = t.decode('ascii')
        except Exception:
            continue
        if ts.isprintable() and sum(ch.isalpha() or ch == '_' for ch in ts) > 0.6 * len(ts):
            best.append((k, ts))
    print("   0x1d6a98 candidates:", best[:8])


if __name__ == "__main__":
    main()
