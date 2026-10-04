"""_sub_core_order.py — final string vocabulary (2-layer XOR post-pass) +
pointer-table discovery: find arrays of 8-byte pointers into the obfuscated
string pool; the pointer order gives the claim-key ORDER of the iOS core.
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


def extract_raw(data, lo, hi):
    """Yield (start, end, stored_key) for every 00-terminated obfuscated run."""
    out = []
    i = lo
    while i < hi:
        if data[i] == 0:
            i += 1
            continue
        j = i
        while j < hi and data[j] != 0 and j - i < 160:
            j += 1
        n = j - i
        if 4 <= n <= 150:
            key = data[j - 1]
            out.append((i, j, key))
        i = j
    return out


def best_decode(data, i, j, key):
    """Try stored key XOR extra 0..255; pick decode with most [a-z_] mass."""
    best = (0.0, None, None)
    for extra in range(256):
        k = key ^ extra
        dec = bytes(c ^ k for c in data[i:j - 1])
        try:
            t = dec.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not all(32 <= ord(c) < 127 for c in t):
            continue
        lw = sum(1 for c in t if c.islower() or c == '_' or c.isdigit())
        if lw < 0.6 * len(t) or not re.search(r"[a-z]{3}", t):
            continue
        sc = lw - 0.1 * len(t)
        if sc > best[0]:
            best = (sc, k, t)
    return best


def main():
    s = macho.slices(IOS_DEV)[0]
    d = s.data
    lo, hi = 0x1d5340, 0x1d5340 + 0x1810   # __DATA,__data
    strings = []
    for i, j, key in extract_raw(d, lo, hi):
        sc, k, t = best_decode(d, i, j, key)
        if t and len(t) >= 4:
            strings.append((i, k, t))
    seen = set()
    uniq = []
    for off, k, t in strings:
        if t in seen:
            continue
        seen.add(t)
        uniq.append((off, k, t))
    print(f"== decoded obfuscated string pool ({len(uniq)} unique) ==")
    for off, k, t in uniq:
        print(f"   {off:#08x} k={k:#04x}  {t!r}")
    with open(os.path.join(HERE, "_sub_core_order_strings.json"), "w") as f:
        json.dump([[o, k, t] for o, k, t in uniq], f, indent=1)

    # ---- pointer tables into the string pool ----
    offs = {o for o, _, _ in strings}
    lo_all = min(offs) if offs else 0
    hi_all = max(offs) if offs else 0
    print(f"\n== pointer tables (8-byte LE into {lo_all:#x}..{hi_all:#x}) ==")
    tables = []
    i = lo
    while i < hi:
        v = struct.unpack_from("<Q", d, i)[0]
        if lo_all <= v <= hi_all:
            run = []
            j2 = i
            while j2 < hi - 8:
                v2 = struct.unpack_from("<Q", d, j2)[0]
                if lo_all <= v2 <= hi_all:
                    run.append((j2, v2))
                    j2 += 8
                else:
                    break
            if len(run) >= 3:
                tables.append(run)
                i = j2
                continue
        i += 8
    for run in tables:
        print(f"  table @ {run[0][0]:#x} ({len(run)} ptrs)")
        for ptr_off, v in run:
            # resolve: string may start at v or v is mid-string
            t = None
            for off, k, txt in strings:
                if off <= v < off + 160:
                    t = txt[v - off:] if txt else None
                    break
            print(f"    -> {v:#08x}  {t!r}")

    # also search pointer tables in __DATA,__const (0x1d4350..0x1d4e98)
    print("\n== pointer tables in __DATA,__const ==")
    for base in range(0x1d4350, 0x1d4e90, 8):
        v = struct.unpack_from("<Q", d, base)[0]
        if lo_all <= v <= hi_all:
            print(f"  {base:#x} -> {v:#x}")


if __name__ == "__main__":
    main()
