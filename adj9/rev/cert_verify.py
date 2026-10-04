"""cert_verify.py — verify descriptor #9 (the APK signing cert SHA-1).

Descriptor #9 of the adj9 signature is `SHA1(cert_s0_0.der)`, the SHA-1 of the
installed app's signing certificate.  Two independent sources must agree:

  1. RUNTIME  — a live JCA MessageDigest inside the nSign window on the device
                produced `fad0f10d…74bd` (WALL_A_SLICE_101.md, STATUS.md R1).
  2. STATIC   — the signing certificate extracted from the actual installed
                APK's v2 signing block.

This script does (2) and compares against (1).  Run it against any APK.

    python cert_verify.py <path-to.apk>

TRAP (cost us a wrong answer once): in the v2 block the `certificates` field is
a *sequence*: a 4-byte length prefix followed by the concatenated certs.  If you
hash the whole sequence you get a 749-byte value and SHA-1 `ff2a16af…`, which
matches nothing and looks like a cert mismatch.  You must step the 4-byte length
inside the sequence and hash the 745-byte cert itself.
"""
import hashlib
import struct
import sys

DESCRIPTOR_9 = "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0


def _u32(b, o):
    return struct.unpack("<I", b[o:o + 4])[0], o + 4


def signing_block(data):
    """Yield (block_id, block_body) for each pair in the APK Signing Block."""
    i = data.rfind(b"PK\x05\x06")
    if i < 0:
        return
    cd = struct.unpack("<I", data[i + 16:i + 20])[0]
    if cd < 24 or data[cd - 16:cd] != b"APK Sig Block 42":
        return
    size2 = struct.unpack("<Q", data[cd - 24:cd - 16])[0]
    p = cd - 8 - size2 + 8
    end = cd - 24
    while p < end and p + 12 <= len(data):
        clen = struct.unpack("<Q", data[p:p + 8])[0]
        idv = struct.unpack("<I", data[p + 8:p + 12])[0]
        yield idv, data[p + 12:p + 8 + clen]
        p += 8 + clen


def v2_certs(data):
    """The certificate DERs in the v2 signer's signed-data certificates field."""
    for idv, body in signing_block(data):
        if idv != V2_BLOCK_ID:
            continue
        slen, o = _u32(body, 0)
        signers = body[o:o + slen]
        slen2, so = _u32(signers, 0)
        signer = signers[so:so + slen2]
        sdlen, sdo = _u32(signer, 0)
        sd = signer[sdo:sdo + sdlen]
        diglen, do = _u32(sd, 0)
        certs_len, co = _u32(sd, do + diglen)
        # `certs` is a SET: its `certs_len` bytes ALREADY include each cert's
        # own uint32 length prefix.  Parse entries inside it directly — adding
        # another +4 here reads the first cert's DER bytes as a length.
        certs = sd[co:co + certs_len]
        q, out = 0, []
        while q + 4 <= len(certs):
            cl, q = _u32(certs, q)
            out.append(certs[q:q + cl])
            q += cl
        return out
    return []


def main(path):
    data = open(path, "rb").read()
    certs = v2_certs(data)
    if not certs:
        print("no v2 certificate found in %s" % path)
        return 2
    print("APK: %s  (%d bytes)" % (path, len(data)))
    print("descriptor #9 (runtime JCA trace) = %s\n" % DESCRIPTOR_9)
    rc = 1
    for n, c in enumerate(certs, 1):
        h = hashlib.sha1(c).hexdigest()
        hit = h == DESCRIPTOR_9
        print("  cert[%d] len=%-4d sha1=%s%s"
              % (n, len(c), h, "   <== MATCHES descriptor #9" if hit else ""))
        if hit:
            rc = 0
    print("\nRESULT: %s" % ("PASS — descriptor #9 confirmed against this APK"
                            if rc == 0 else
                            "FAIL — no cert in this APK hashes to descriptor #9"))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "devpull/base.apk"))
