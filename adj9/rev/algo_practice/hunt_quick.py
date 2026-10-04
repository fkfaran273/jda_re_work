"""hunt_quick.py — cheap no-VM hypotheses for the 17 unknown dwords.

A. block: is record[46:78) == blob[46:78) (self-copy) or from elsewhere?
B. digest: is blob[160:192) the CBC cipher continuing 2 more chunks after
   the record (i.e. whiten(X, WA=blob[144:160)) || whiten(Y, WA=prev))?
   Try a battery of plaintext candidates for X and Y.
C. digest: simple digest compositions over blob[:160) / record.
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(HERE)
sys.path.insert(0, REV)
from whiten_decoder import (whiten_body_inverse, whiten_forward,  # noqa
                            whiten_chunk, T_HEX, KB_HEX, PI)
from forward_known import parse_win_blobs, rebuild_record  # noqa: E402

SHA0 = hashlib.sha256(b"").digest()


def candidates(rec, header, blob):
    """16-B plaintext candidates for the digest chunks."""
    cands = {
        "zeros": b"\x00" * 16,
        "SHA0[0:16]": SHA0[:16], "SHA0[16:32]": SHA0[16:32],
        "header": header,
        "rec[0:16)": rec[0:16], "rec[16:32)": rec[16:32],
        "rec[112:128)": rec[112:128], "rec[128:144)": rec[128:144],
        "0e*14+0000": rec[130:144] + b"\x00\x00",
        "0000+0e*14": b"\x00\x00" + rec[130:144],
        "S*4": rec[20:24] * 4,
        "cert[0:16)": rec[25:41], "cert[4:20)": rec[29:45],
        "magic3+pad": b"\x01\x00\x08" + b"\x00" * 13,
        "0xff*16": b"\xff" * 16,
        "blob[0:16)": blob[0:16],
        "blob[144:160)": blob[144:160],
    }
    return cands


def main():
    blobs = parse_win_blobs()
    print("wins: %d" % len(blobs))

    # ---- A. block location ------------------------------------------------
    print("\n== A. block == blob[46:78)? ==")
    for i, blob in enumerate(blobs):
        rec = whiten_body_inverse(blob[16:160], blob[:16])
        same = rec[46:78] == blob[46:78]
        print("win%d block==blob[46:78): %s" % (i, same))

    # ---- B. digest as CBC continuation ------------------------------------
    print("\n== B. digest = 2 more CBC chunks ==")
    hits = 0
    for i, blob in enumerate(blobs):
        rec = whiten_body_inverse(blob[16:160], blob[:16])
        wa1 = blob[144:160]
        for xn, xv in candidates(rec, blob[:16], blob).items():
            c1 = whiten_chunk(xv, wa1)
            if c1 != blob[160:176]:
                continue
            wa2 = c1
            for yn, yv in candidates(rec, blob[:16], blob).items():
                c2 = whiten_chunk(yv, wa2)
                if c2 == blob[176:192]:
                    print("win%d HIT: X=%s Y=%s" % (i, xn, yn))
                    hits += 1
    print("CBC-continuation hits: %d" % hits)

    # ---- C. digest as plain digests ---------------------------------------
    print("\n== C. digest as digests of known material ==")
    hits2 = 0
    for i, blob in enumerate(blobs):
        rec = whiten_body_inverse(blob[16:160], blob[:16])
        msgs = {"blob[:160)": blob[:160], "record": rec,
                "blob[:160)+header": blob[:160] + blob[:16],
                "record+header": rec + blob[:16]}
        fns = {"sha256": lambda b: hashlib.sha256(b).digest(),
               "sha512[:32]": lambda b: hashlib.sha512(b).digest()[:32],
               "sha1+sha1": lambda b: hashlib.sha1(b).digest() * 2}
        for mn, mb in msgs.items():
            for fnn, fn in fns.items():
                d = fn(mb)
                if d[:32] == blob[160:192]:
                    print("win%d HIT: %s(%s)" % (i, fnn, mn))
                    hits2 += 1
    print("digest-composition hits: %d" % hits2)


if __name__ == "__main__":
    main()
