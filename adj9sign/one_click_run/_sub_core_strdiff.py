"""_sub_core_strdiff.py — strings cross-diff between the Android native
(libsigner.so, AAR v5.0.0) and the iOS cores (dynamic xcframework device +
simulator slices, static .a), plus Mach-O symtab of the static archive and
the AAR's classes.jar listing.

Outputs console tables + _sub_core_strdiff_out.json
"""
import io
import json
import os
import re
import struct
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _sub_core_macho as macho

D = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins"
AND_SO = os.path.join(D, "extracted/aar/jni/arm64-v8a/libsigner.so")
IOS_DEV = os.path.join(D, "extracted/xcframework_dyn/AdjustSigSdk.xcframework/"
                          "ios-arm64/AdjustSigSdk.framework/AdjustSigSdk")
IOS_SIM = os.path.join(D, "extracted/xcframework_dyn/AdjustSigSdk.xcframework/"
                          "ios-arm64_x86_64-simulator/AdjustSigSdk.framework/AdjustSigSdk")
IOS_STATIC_A = os.path.join(D, "extracted/static_a/AdjustSigSdk.a")
AAR = os.path.join(D, "adjust-android-signature-5.0.0.aar")

KEYNAMES = ["endpoint", "client_sdk", "activity_kind", "algorithm",
            "secret_id", "adj_signing_id", "headers_id", "native_version",
            "control_params", "os_name", "idfv", "idfa", "receipt",
            "locale", "timezone", "source", "params", "sig", "signing",
            "device", "app", "track", "att", "sha", "payload", "body",
            "header", "record", "whiten", "digest", "block", "claim",
            "signature", "android", "ios", "5.0.0", "5.7.0", "5.8.0"]

SEL_HINTS = ["appStoreReceiptURL", "NSLocale", "NSTimeZone", "CFUUID",
             "locale", "timezone", "receipt", "identifierForVendor",
             "advertisingIdentifier", "UUID", "currentLocale", "localTimeZone",
             "name", "copy", "bundle"]


def strings_of(data, minlen=4):
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % minlen)
    return [(m.start(), m.group().decode("ascii")) for m in pat.finditer(data)]


def elf_sections(data):
    """name -> (offset, size) for ELF64."""
    if data[:4] != b"\x7fELF":
        return {}
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, o)
        secs.append([name, typ, off, size])
    shstr = secs[e_shstrndx]
    strtab = data[shstr[2]:shstr[2] + shstr[3]]
    out = {}
    for name, typ, off, size in secs:
        nm = strtab[name:strtab.find(b"\x00", name)].decode(errors="replace")
        out[nm] = (off, size)
    return out


def elf_sec_of(secs, off):
    for nm, (o, s) in secs.items():
        if nm != "" and o <= off < o + s and nm != ".shstrtab":
            return nm
    return "?"


def ios_strings(path):
    sl = macho.slices(path)
    out = {}
    for s in sl:
        arr = []
        for seg, sec in s.sections():
            if sec["size"] == 0:
                continue
            blob = s.data[sec["fileoff"]:sec["fileoff"] + sec["size"]]
            if sec["sect"] in ("__cstring", "__objc_methname", "__objc_methtype",
                               "__objc_classname", "__oslogstring", "__const",
                               "__data", "__unwind_info"):
                for off, txt in strings_of(blob, 4):
                    arr.append((sec["fileoff"] + off, sec["sect"], txt))
        out[s.name] = arr
    return out


def main():
    result = {}

    # ---------------- Android .so ----------------
    and_data = open(AND_SO, "rb").read()
    and_secs = elf_sections(and_data)
    and_strs = [(off, elf_sec_of(and_secs, off), t) for off, t in strings_of(and_data)]
    print(f"== Android libsigner.so: {len(and_strs)} strings (>=4)")
    and_key = [(o, s, t) for o, s, t in and_strs
               if any(k in t.lower() for k in KEYNAMES)]
    for o, s, t in and_key:
        print(f"   {o:#08x} {s:<10} {t[:90]}")
    result["android"] = {"n_strings": len(and_strs),
                         "key": [[o, s, t] for o, s, t in and_key],
                         "all": [[o, s, t] for o, s, t in and_strs]}

    # ---------------- iOS dynamic device ----------------
    dev = ios_strings(IOS_DEV)
    print(f"\n== iOS device arm64 strings by section:")
    for name, arr in dev.items():
        print(f"  slice {name}: {len(arr)} strings")
        for o, sec, t in arr:
            print(f"   {o:#08x} {sec:<16} {t[:100]}")
    result["ios_device"] = {name: [[o, sec, t] for o, sec, t in arr]
                            for name, arr in dev.items()}

    # ---------------- iOS static .a: members + symtab ----------------
    raw = open(IOS_STATIC_A, "rb").read()
    members = []
    pos = 8
    while pos < len(raw) - 60:
        hdr = raw[pos:pos + 60]
        if hdr[:3] == b"\x00\x00" or hdr[-2:] != b"\x60\x0a":
            break
        name = hdr[:16].decode(errors="replace").strip()
        size = int(hdr[48:58].decode().strip())
        body = raw[pos + 60: pos + 60 + size]
        members.append((name, size, body))
        pos += 60 + size + (size & 1)
    print(f"\n== static .a members: {[(n, s) for n, s, _ in members]}")
    sta = {}
    for name, size, body in members:
        if body[:4] == b"\xcf\xfa\xed\xfe":
            sl = macho.slices.__wrapped__ if False else None
            # thin mach-o member: parse manually
            ss = macho.Slice(name, "thin-" + name, 0, len(body))
            ss._data = body
            ss.path = name
            ss.parse()
            syms = read_symtab(ss)
            strs = strings_of(body)
            print(f"  member {name}: {len(syms)} symbols, {len(strs)} strings")
            for sname, val in syms[:200]:
                print(f"     sym {val:#x} {sname}")
            sta[name] = {"syms": syms, "n_strings": len(strs)}
    result["static_a"] = {n: {"syms": v["syms"][:500]} for n, v in sta.items()}

    # ---------------- AAR classes.jar ----------------
    with zipfile.ZipFile(AAR) as z:
        cj = [n for n in z.namelist() if n.endswith(".class")]
        print(f"\n== AAR classes.jar: {len(cj)} classes")
        for n in sorted(cj):
            print("   ", n)
        result["aar_classes"] = sorted(cj)

    with open(os.path.join(HERE, "_sub_core_strdiff_out.json"), "w") as f:
        json.dump(result, f, indent=1)
    print("\nwrote _sub_core_strdiff_out.json")


def read_symtab(s):
    """LC_SYMTAB symbols of a parsed Slice (thin)."""
    d = s.data
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, res = \
        struct.unpack_from("<IiiIIIII", d, 0)
    off = 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", d, off + 8)
            strtab = d[stroff:stroff + strsize]
            for i in range(nsyms):
                o = symoff + i * 16
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(
                    "<IBBII", d, o)
                end = strtab.find(b"\x00", n_strx)
                nm = strtab[n_strx:end].decode(errors="replace")
                out.append((nm, n_value))
        off += cmdsize
    return out


if __name__ == "__main__":
    main()
