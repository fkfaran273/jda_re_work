#!/usr/bin/env python3
"""appdiff.py -- extract every APP-SPECIFIC adj9 input from an adj9-signed APK.

    python appdiff.py <path-to-apk-or-dir> [--lib <known_libsigner.so>] [--outdir <dir>]

Target: one .apk, or a dir whose *.apk files are probed for
lib/arm64-v8a/libsigner.so (split APKs carry it in split_config.arm64_v8a.apk).
--lib: reference build for the SAME/DIFFERENT verdict; --outdir: span-extract
dir on a DIFFERENT build (defaults: penti lib; <apk-dir>/appdiff_spans).

The adj9 algorithm (VM, whitening, descriptor order, header law) is UNIVERSAL:
adj9sign/signer_simple.py.  The five APP-SPECIFIC inputs:
  1. libsigner.so build             -> APPENDIX _LIB_SPANS
  2. D9 = signing-cert SHA-1        -> DESC9   (APK Signing Block, v2/v3)
  3. adj_signing_id / headers_id / native_version / adj_verification /
     Client-SDK (ONE captured Authorization header) -> ADJ_SIGNING_ID /
     auth_header() / NATIVE_VERSION / ADJ_VERIFICATION / CLIENT_SDK
  4. app_token / package_name / app_version -> run_simple.py
  5. D8 = 16-B flags (whiten_decoder.py on ONE captured blob) -> DESC8
Pure stdlib (capstone NOT needed).  Full method: adj9/rev/APPDIFF_METHOD.md.
"""
import argparse
import base64
import hashlib
import os
import re
import ssl
import struct
import sys
import tempfile
import zipfile

# The three libsigner.so code spans (vaddr == file offset) carrying the VM.
LIB_SPANS = [(0x99000, 0xBCA30), (0x100094, 0x12AA48), (0x146000, 0x149000)]
LIB_MEMBER = "lib/arm64-v8a/libsigner.so"
SIG_MAGIC = b"APK Sig Block 42"
CERT_BLOCK_IDS = {0x7109871a: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}
# default reference lib: <workspace>/extracted/arm64/lib/arm64-v8a/libsigner.so
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LIB = os.path.normpath(os.path.join(
    HERE, "..", "..", "extracted", "arm64", "lib", "arm64-v8a", "libsigner.so"))


def _find_carrier(directory):
    """Return the first *.apk under directory whose zip contains LIB_MEMBER."""
    paths = [os.path.join(r, f) for r, _d, fs in os.walk(directory)
             for f in sorted(fs) if f.lower().endswith(".apk")]
    for path in paths:                      # scan zip members, pick lib carrier
        try:
            with zipfile.ZipFile(path) as z:
                if LIB_MEMBER in z.namelist():
                    print("[apk] %d candidate(s); picked %s (carries %s)"
                          % (len(paths), path, LIB_MEMBER))
                    return path
        except zipfile.BadZipFile:
            continue
    return None


def find_apk(target):
    """Resolve target to one APK (dir mode: probe zips for the lib member)."""
    if os.path.isfile(target):
        return target
    if not os.path.isdir(target):
        sys.exit("not a file or directory: %s" % target)
    if not [f for _r, _d, fs in os.walk(target) for f in fs
            if f.lower().endswith(".apk")]:
        sys.exit("no *.apk found under %s" % target)
    carrier = _find_carrier(target)
    if not carrier:
        sys.exit("no *.apk under %s contains %s" % (target, LIB_MEMBER))
    return carrier


def read_signing_block(data):
    """{pair-id: value} of the APK Signing Block (v2 layout: [size1 u64]
    [pairs...][size2 u64][magic 16B] immediately before the central dir)."""
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        sys.exit("no EOCD -- not a ZIP?")
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    start, size2 = None, 0
    if cd_off > 40 and data[cd_off - 16:cd_off] == SIG_MAGIC:
        size2 = struct.unpack_from("<Q", data, cd_off - 24)[0]
        start = cd_off - (size2 + 8)        # size1 sanity check
        if struct.unpack_from("<Q", data, start)[0] != size2:
            start = None
    if start is None:                       # fallback: locate magic directly
        pos = data.rfind(SIG_MAGIC)
        if pos < 8:
            sys.exit("no APK Signing Block magic -- not a v2/adj9-signed APK?")
        size2 = struct.unpack_from("<Q", data, pos - 8)[0]
        start = pos + 16 - (size2 + 8)
    pairs, off, end = {}, start + 8, start + 8 + (size2 - 24)
    while off + 12 <= end:                  # walk length-prefixed id/value pairs
        plen = struct.unpack_from("<Q", data, off)[0]
        pid = struct.unpack_from("<I", data, off + 8)[0]
        if plen < 4 or off + 8 + plen > len(data):
            break
        pairs[pid] = data[off + 12:off + 8 + plen]
        off += 8 + plen
    return pairs


def certs_from_block(val):
    """Walk the v2/v3 signer structure: LP signers -> signer = LP{signed_data,
    signatures, public_key}; signed_data = LP{digests, certificates, attrs};
    certificates = LP sequence of LP X509 DERs.  Returns [DER, ...]."""
    def lp(buf, off):                       # length-prefixed blob (u32 LE len)
        n = struct.unpack_from("<I", buf, off)[0]
        return buf[off + 4:off + 4 + n], off + 4 + n
    try:
        signers, _ = lp(val, 0)
        out, off = [], 0
        while off + 4 <= len(signers):
            signer, off = lp(signers, off)
            sd, _ = lp(signer, 0)           # signed data (signatures/pk skipped)
            _, o2 = lp(sd, 0)               # digests
            certseq, _ = lp(sd, o2)         # certificates (container bytes)
            co = 0
            while co + 4 <= len(certseq):   # each = LP X509 DER
                cert, co = lp(certseq, co)
                out.append(cert)
        return out
    except (struct.error, IndexError):
        return []


def certs_rawscan(buf):
    """Last-resort fallback if the structural walk finds nothing: every
    30 82 xx xx that parses as a DER SEQUENCE (tbsCertificate at +4)."""
    out = []
    for m in re.finditer(b"\x30\x82", buf):
        o = m.start()
        if o + 4 > len(buf):
            continue
        n = struct.unpack_from(">H", buf, o + 2)[0]
        # sane size, in bounds, inner SEQUENCE (tbsCertificate)
        if n < 60 or o + 4 + n > len(buf) or buf[o + 4:o + 5] != b"\x30":
            continue
        out.append(buf[o:o + 4 + n])
    return out


def cert_info(der):
    """SHA-1 + subject via stdlib only: ssl._ssl._test_decode_cert on a temp
    PEM file (private-but-stable API, the same one ssl's own tests use)."""
    sha1 = hashlib.sha1(der).hexdigest()
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der).encode())
        d = ssl._ssl._test_decode_cert(path)
        subj = ", ".join("%s=%s" % (k, v)
                         for rdn in d.get("subject", ()) for k, v in rdn)
        serial = d.get("serialNumber", "?")
    except Exception as e:                  # keep the SHA-1 even on failure
        subj, serial = "<decode failed: %s>" % e, "?"
    finally:
        os.unlink(path)
    return sha1, subj, serial


def report_certs(pairs):
    """Print every signing-block certificate (deduped); flag the leaf (last
    cert of the first signer chain) as the D9 descriptor source."""
    leaf_sha1, ordered, seen = None, [], set()
    for pid in (0x7109871a, 0xF05368C0, 0x1B93AD61):    # v2, v3, v3.1
        certs = certs_from_block(pairs.get(pid, b""))
        for i, der in enumerate(certs):
            if der not in seen:
                seen.add(der)
                ordered.append((CERT_BLOCK_IDS[pid], i, der))
        if certs and leaf_sha1 is None:     # chain leaf = last cert
            leaf_sha1 = hashlib.sha1(certs[-1]).hexdigest()
    if not ordered:                         # exotic wrapper? raw-scan instead
        ordered = [(None, None, d) for d in certs_rawscan(b"".join(pairs.values()))]
    if not ordered:
        print("[cert] NO certificates found -- APK is not v2/v3-signed")
        return None
    for tag, i, der in ordered:
        sha1, subj, serial = cert_info(der)
        leaf = "  <== LEAF cert -> this SHA-1 is the D9 descriptor" \
            if sha1 == leaf_sha1 else ""
        head = ("%s signer #%d" % (tag, i + 1)) if tag else "raw-scan extra"
        print("[cert] %s: len=%dB sha1=%s serial=%s%s\n"
              "       subject: %s" % (head, len(der), sha1, serial, leaf, subj))
    return leaf_sha1


def report_manifest(zf):
    """Best-effort package/versionName from the BINARY AndroidManifest.xml:
    yank UTF-16LE + ASCII string runs, list dotted candidates (a hint only --
    binary AXML has no plain 'package=' text)."""
    try:
        raw = zf.read("AndroidManifest.xml")
    except KeyError:
        print("[manifest] AndroidManifest.xml missing")
        return None, None
    runs = []
    for pat, how in ((rb"(?:[\x20-\x7e]\x00){3,}", "utf-16-le"),  # AXML pool
                     (rb"[\x20-\x7e]{3,}", "ascii")):
        runs += [m.group().decode(how) for m in re.finditer(pat, raw)]
    pkgs, vers = [], []
    for s in runs:
        if re.fullmatch(r"[a-zA-Z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){1,6}", s):
            pkgs.append(s)
        elif re.fullmatch(r"\d+(?:\.\d+){1,3}(?:[-.+]\w+)?", s) and len(s) <= 24:
            vers.append(s)
    # demote SDK/framework noise; recover UTF-8-pool length-byte mangling
    # ("Kcom.google..." = len byte 0x4B + string); the real applicationId is
    # the candidate that PREFIXES the most other candidates (components).
    NOISE = ("com.android.", "com.google.", "com.facebook.", "androidx",
             "kotlin", "org.apache", "java", "junit")
    cands = set(pkgs)
    for s in pkgs:
        if len(s) > 4 and s[1:] not in cands and re.match(
                r"(?:com|org|net|io|de|fr)\.[A-Za-z0-9_.]+$", s[1:]):
            cands.add(s[1:])
    pref = {c: sum(1 for o in cands if o.startswith(c + ".")) for c in cands}
    pkgs = sorted(cands, key=lambda c: (c.lower().startswith(NOISE),
                                        -pref[c], -c.count(".")))
    vers = list(dict.fromkeys(vers))
    print("[manifest] BEST-EFFORT (binary AXML string scan):")
    print("  package candidates : %s" % (", ".join(pkgs[:6]) or "(none found)"))
    print("  version candidates : %s" % (", ".join(vers[:6]) or "(none found)"))
    return (pkgs[0] if pkgs else None), (vers[0] if vers else None)


def report_lib(apk, zf, known_lib, outdir):
    """sha256+size of the app's libsigner.so vs the known build; on a
    DIFFERENT build cut the three VM spans and emit a paste-ready _LIB_SPANS
    snippet for signer_simple.py.  Returns the verdict string.  A base-split
    APK carries no lib -- sibling splits are probed for the carrier."""
    src, z = apk, zf
    if LIB_MEMBER not in zf.namelist():
        print("[lib] this APK has no %s (base split?) -- probing siblings"
              % LIB_MEMBER)
        carrier = _find_carrier(os.path.dirname(os.path.abspath(apk)))
        if not carrier:
            print("[lib] no sibling APK carries the lib -- verdict UNKNOWN")
            return "UNKNOWN (no lib member found)"
        src, z = carrier, zipfile.ZipFile(carrier)
        print("[lib] lib carrier: %s" % carrier)
    lib = z.read(LIB_MEMBER)
    if z is not zf:
        z.close()
    sha256 = hashlib.sha256(lib).hexdigest()
    print("[lib] %s: sha256=%s size=%d" % (LIB_MEMBER, sha256, len(lib)))
    if not (known_lib and os.path.isfile(known_lib)):
        print("[lib] no known lib to compare (--lib missing): verdict UNKNOWN")
        return "UNKNOWN (no reference lib)"
    kb = open(known_lib, "rb").read()
    ksha = hashlib.sha256(kb).hexdigest()
    print("[lib] known  : sha256=%s size=%d (%s)" % (ksha, len(kb), known_lib))
    if ksha == sha256:
        print("[lib] VERDICT: SAME-BUILD (byte-identical) -- APPENDIX "
              "_LIB_SPANS stays as is")
        return "SAME-BUILD (byte-identical)"
    print("[lib] VERDICT: DIFFERENT-BUILD -- re-extracting the three spans")
    os.makedirs(outdir, exist_ok=True)
    snippet = ["# paste into signer_simple.py APPENDIX (_LIB_SPANS):",
               "_LIB_SPANS = ["]
    for a, b in LIB_SPANS:
        span = lib[a:b]                     # vaddr == file offset for these
        with open(os.path.join(outdir, "span_%08X-%08X.bin" % (a, b)), "wb") as fh:
            fh.write(span)
        snippet.append('    (0x%X, 0x%X,\n     "%s"),'
                       % (a, b, base64.b64encode(span).decode()))
        print("[lib]   span_%08X-%08X.bin: %d bytes" % (a, b, len(span)))
    with open(os.path.join(outdir, "_LIB_SPANS_snippet.py"), "w") as fh:
        fh.write("\n".join(snippet + ["]"]) + "\n")
    print("[lib] spans + paste-ready snippet -> %s" % outdir)
    return "DIFFERENT-BUILD (spans re-extracted)"


def print_checklist(leaf_sha1, pkg, ver, verdict):
    """5-item SWAP CHECKLIST: extracted values filled in, capture-only fields
    blank, with the landing spot of each value in signer_simple/run_simple."""
    print("=" * 74 + "\nSWAP CHECKLIST -- app-specific adj9 inputs "
          "(algorithm = universal)\n" + "=" * 74)
    print('[1] libsigner.so build : %s   -> APPENDIX _LIB_SPANS\n'
          '[2] D9 descriptor      : %s   (signing-cert SHA-1) -> DESC9\n'
          '[3] header constants   : adj_signing_id="______"  headers_id="___"\n'
          '        native_version="_______"  Client-SDK="__________"\n'
          '        adj_verification="__________________________"\n'
          '      <- from ONE captured Authorization header -> ADJ_SIGNING_ID /\n'
          '         auth_header() / NATIVE_VERSION / ADJ_VERIFICATION / CLIENT_SDK\n'
          '[4] app identity       : app_token="____________"  package_name=%s\n'
          '        app_version=%s   (app_token: capture or dex hunt)\n'
          '      -> run_simple.py APP_TOKEN / params["package_name"] / app_version\n'
          '[5] D8 descriptor      : ______________________________  (16-B hex)\n'
          '      (decode ONE captured blob: python whiten_decoder.py <b64>) -> DESC8\n'
          'VERIFY : whiten-decode the captured blob and diff vs a minted one; then\n'
          'one live funnel (run_simple.py: click -> /session -> /sdk_click ->\n'
          '/attribution must come back non-Organic).'
          % (verdict, leaf_sha1 or "________(no cert found)",
             '"%s"' % pkg if pkg else '"____________"',
             '"%s" (best-effort)' % ver if ver else '"_______"'))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="extract app-specific adj9 inputs from an APK")
    ap.add_argument("target", help="APK file or directory containing APKs")
    ap.add_argument("--lib", default=DEFAULT_LIB,
                    help="known libsigner.so for build comparison")
    ap.add_argument("--outdir", default=None,
                    help="span extract dir on DIFFERENT-BUILD (default "
                         "<apk-dir>/appdiff_spans)")
    args = ap.parse_args(argv)
    apk = find_apk(args.target)
    print("[apk] %s (%d bytes)" % (apk, os.path.getsize(apk)))
    pairs = read_signing_block(open(apk, "rb").read())
    print("[block] signing block pair ids: %s"
          % ", ".join("0x%08x" % k for k in sorted(pairs)))
    leaf_sha1 = report_certs(pairs)
    zf = zipfile.ZipFile(apk)
    pkg, ver = report_manifest(zf)
    outdir = args.outdir or os.path.join(
        os.path.dirname(os.path.abspath(apk)), "appdiff_spans")
    verdict = report_lib(apk, zf, args.lib, outdir)
    zf.close()
    print_checklist(leaf_sha1, pkg, ver, verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main())
