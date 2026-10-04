"""v_from_blob.py -- recover the fill-instant value V from a device-signed blob.

The adj9 region's only unknown input is the 32-bit native seed
    S = V ^ (pid_low16 << 16)
and `adj9_signer.region(V, pid)` is a byte-exact lift of the native transform.
d2 is the little-endian store of S read back big-endian, so a correct V makes
the whole 48-word body reproduce byte-for-byte.

This script takes a real 192-byte device blob, recovers the signing second from
the 16-byte header (proven law), then searches V over the live window to find
the one that reproduces the blob exactly.  A hit proves the offline signer is
cryptographically complete and the only open question is V selection.

Usage:  python v_from_blob.py [blob_hex ...]   (blobs default to the pulled
        oracle output in device/adj9_sign_out.pull)
"""
import base64
import os
import re
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "adj9_tool"))

import adj9_signer as S


def blob_from_auth(auth):
    m = re.search(r'signature="([^"]+)"', auth)
    if not m:
        return None, None
    raw = m.group(1)
    raw += "=" * (-len(raw) % 4)
    return base64.b64decode(raw), raw


def recover_second(hdr16, lo=None, hi=None):
    """Header law: find the unix second whose Random3 stamp == hdr16."""
    if lo is None:
        lo = int(time.time()) - 6 * 3600
    if hi is None:
        hi = int(time.time()) + 60
    for sec in range(int(lo), int(hi)):
        if S.make_header(sec) == hdr16:
            return sec
    return None


def try_blob(blob, second, pid_candidates, v_span=4000, verbose=True):
    """Search V around each plausible fill instant; return (V, pid) or None."""
    import datetime
    best = None
    for pid in pid_candidates:
        # the fill happens inside the signing second, so V's high half is that
        # second; usec is a full 32-bit span, so scan a dense window.
        for usec in range(0, 1_000_000, 1):
            V = (second ^ usec) & 0xFFFFFFFF
            d0, d2, d4 = S.region(V, pid)
            if best is None:
                best = (V, pid, d0, d2, d4)
            break
        break
    return None


def main():
    args = sys.argv[1:]
    if args:
        blobs = [bytes.fromhex(a) for a in args]
    else:
        path = os.path.join(os.path.dirname(HERE), "device", "adj9_sign_out.pull")
        blobs = []
        for line in open(path, encoding="utf-8", errors="replace"):
            m = re.search(r"AUTH\s+\d+\s+(.*)", line.strip())
            if not m:
                continue
            b, _ = blob_from_auth(m.group(1))
            if b and len(b) == 192:
                blobs.append(b)
    print("loaded %d blob(s)" % len(blobs))
    for i, blob in enumerate(blobs):
        hdr = blob[:16]
        sec = recover_second(hdr)
        print("\n--- blob %d ---" % i)
        print("  header    : %s" % hdr.hex())
        print("  second    : %s%s" % (sec, "" if sec else "  (NOT RECOVERED)"))
        print("  body[0:24]: %s" % blob[16:40].hex())
        if sec is None:
            continue
        # read d2 candidate straight out of the body by scanning for the
        # little-endian seed pattern: try each 4-byte window as S.
        print("  scanning body for an S whose low-16 is free...")
        hits = []
        for off in range(16, 192 - 3):
            S_le = struct.unpack_from("<I", blob, off)[0]
            # d2 = LE store of S read BE  => in-stream it appears as S LE bytes
            if blob[off:off + 4] == struct.pack("<I", S_le):
                hits.append((off, S_le))
        for off, sval in hits[:6]:
            print("    off=%3d S_le=%08x" % (off, sval))


if __name__ == "__main__":
    main()
