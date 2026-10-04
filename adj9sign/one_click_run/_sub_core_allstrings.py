"""_sub_core_allstrings.py — complete extraction of the iOS core's XOR-keyed
obfuscated strings from __DATA,__data (and any other section).

Scheme (verified): each string is stored as plaintext XOR k for a per-string
key byte k, and the encoded stream ends with the byte k itself (since the
plaintext terminator NUL XOR k == k), followed by 00 padding to alignment.

Extractor: walk every offset; if bytes[i] != 0 and XOR-decoding with key
bytes[i] (found by scanning ahead to the first 00) yields printable ASCII,
emit the string.  Dedup overlapping hits.
"""
import os
import re
import struct
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _sub_core_macho as macho

IOS_DEV = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins/extracted/xcframework_dyn/AdjustSigSdk.xcframework/ios-arm64/AdjustSigSdk.framework/AdjustSigSdk"


def extract(data, lo, hi):
    out = []
    i = lo
    while i < hi:
        b = data[i]
        if b == 0:
            i += 1
            continue
        # candidate string start; find terminator (first 00) within 128 bytes
        j = i
        while j < hi and data[j] != 0 and j - i < 128:
            j += 1
            n = j - i
            if 4 <= n <= 120:
                key = data[j - 1] if j < hi else 0
                dec = bytes(c ^ key for c in data[i:j])
                txt = dec[:-1]
                if txt and all(32 <= c < 127 for c in txt):
                    try:
                        t = txt.decode("ascii")
                        alpha = sum(1 for c in t if c.isalpha() or c == '_')
                        if alpha >= 4 and alpha >= 0.55 * len(t):
                            out.append((i, key, t))
                            i = j
                            continue
                    except UnicodeDecodeError:
                        pass
        i += 1
    return out


def main():
    s = macho.slices(IOS_DEV)[0]
    results = {}
    for seg, sec in s.sections():
        if sec["sect"] in ("__data", "__const", "__bss", "__cstring"):
            if sec["sect"] == "__bss":
                continue
            fo, sz = sec["fileoff"], sec["size"]
            if sz == 0:
                continue
            hits = extract(s.data, fo, fo + sz)
            results[sec["sect"]] = hits
            print(f"== __DATA,{sec['sect']} @ {fo:#x} size {sz:#x}: {len(hits)} obfuscated strings")
            for off, key, txt in hits:
                print(f"   {off:#08x} k={key:#04x}  {txt!r}")
    with open(os.path.join(HERE, "_sub_core_allstrings_out.json"), "w") as f:
        json.dump({k: [[o, kk, t] for o, kk, t in v] for k, v in results.items()},
                  f, indent=1)
    print("\nwrote _sub_core_allstrings_out.json")


if __name__ == "__main__":
    main()
