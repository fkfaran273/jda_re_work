"""hsbc_3_byteexact.py -- task 4: full 192-byte blob rebuild vs the capture.

For each kind: rebuild with P.sign(second, seed, claims, cert, phase) from the
capture's own second/seed/fields, and via P.sign_request (the production path)
with an HSBC campaign dict; compare the full Authorization header string.
Offline only.
"""
import base64
import sys

import hsbc_lib as L
import adj9_pure as P
import adj9_decode as D


def diff_region(ours, theirs):
    for i in range(min(len(ours), len(theirs))):
        if ours[i] != theirs[i]:
            region = ("header 0:16" if i < 16 else
                      "body 16:160" if i < 160 else "digest 160:192")
            return "first diff at byte %d (%s): ours %02x theirs %02x" % (
                i, region, ours[i], theirs[i])
    return None


def main():
    results = {}

    for sid in ("07", "08", "09"):
        e = L.parse_entry(sid)
        kind, blob, f, env = e["kind"], e["blob"], e["fields"], e["env"]
        print("=" * 72)
        print("%s / %s" % (sid, kind))

        rec = D.whiten_body_inverse(blob[16:160], blob[:16])
        seed = int.from_bytes(rec[20:24], "big")
        head, cert, blk = rec[3:19], rec[25:45], rec[46:78]

        sec = next(s for s in range(1792142976 - 600, 1792142976 + 600)
                   if P.make_header(s) == blob[:16])
        # the attribution second differs; re-derive properly
        base_c = L.ts_to_unix(f["created_at"])
        sec = next((base_c + d for d in range(-600, 601)
                    if P.make_header(base_c + d) == blob[:16]), None)

        # -- the claims exactly as our law builds them from the posted map ----
        val = dict(f)
        val.update({"activity_kind": kind, "client_sdk": e["client_sdk"],
                    "adj_signing_id": env["adj_signing_id"],
                    "headers_id": env["headers_id"],
                    "native_version": env["native_version"],
                    "adj_verification": env["adj_verification"]})
        padded, n = P.claims_padded(val, kind)

        ours = P.sign(sec, seed, padded[:n], cert, (0x40,))
        verdict_exact = ours == blob
        print("  raw P.sign rebuild vs blob :",
              "EXACT" if verdict_exact else "MISMATCH -- " + diff_region(ours, blob))
        if not verdict_exact:
            for name, sl in (("header", slice(0, 16)), ("body", slice(16, 160)),
                             ("digest", slice(160, 192))):
                print("    %s ours   %s" % (name, ours[sl].hex()))
                print("    %s theirs %s" % (name, blob[sl].hex()))

        # -- production path: sign_request with an HSBC campaign dict ---------
        camp = {"cert_sha1": cert.hex(),
                "adj_signing_id": env["adj_signing_id"],
                "headers_id": env["headers_id"],
                "native_version": env["native_version"],
                "adj_verification": env["adj_verification"],
                "client_sdk": e["client_sdk"],
                "head_phase": (0x40,)}
        auth_ours = P.sign_request(dict(f), kind, camp, second=sec, seed=seed,
                                   head=(0x40,))
        auth_theirs = e["auth"]
        hdr_match = auth_ours == auth_theirs
        print("  sign_request Authorization == capture:",
              "EXACT" if hdr_match else "MISMATCH")
        if not hdr_match:
            for i, (a, b) in enumerate(zip(auth_ours, auth_theirs)):
                if a != b:
                    print("    first header-string diff at char %d" % i)
                    print("    ours  : %s" % auth_ours[max(0, i - 30):i + 60])
                    print("    theirs: %s" % auth_theirs[max(0, i - 30):i + 60])
                    break
            else:
                print("    length diff: ours %d theirs %d" %
                      (len(auth_ours), len(auth_theirs)))
        results[kind] = verdict_exact and hdr_match

    print("=" * 72)
    print("SUMMARY: " + ", ".join("%s=%s" % (k, "EXACT" if v else "MISMATCH")
                                  for k, v in results.items()))


if __name__ == "__main__":
    main()
