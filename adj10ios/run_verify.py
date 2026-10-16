# -*- coding: utf-8 -*-
"""run_verify.py -- carve + per-layer-verify ANY adj7-iOS capture.

    python run_verify.py <file.saz>

Per blob: L0 304 B structure | L1 tag (DK37) | L2 record decrypt (SEED,
cert40 ascii-0, padding) | L3 MINSTD header second (unique, inside the
sent_at..wire window) | L4 claims/H (+ the /sdk_info kind probe) |
L5 byte-exact mint.
"""
import re
import sys

import adj7ios_pure as sg
from make_gold import INFO_CANDIDATES, KIND_MAP, carve, to_epoch


def verify(rec):
    blob = bytes.fromhex(rec["sig"])
    r = {"sid": rec["sid"], "endpoint": rec["endpoint"]}
    r["L0"] = len(blob) == 304
    r["L1"] = sg.verify_tag(blob)
    plain = sg.cbc_decrypt(blob[16:272], blob[:16])
    m = re.match(sg.RECORD_RE, plain)
    r["L2"] = bool(m) and plain.endswith(b"\x10" * 16) \
        and m.group(3) == sg.CERT40_IOS
    if not m:
        return r, None, None
    nonce12 = (int(m.group(1).decode().strip()).to_bytes(8, "little")
               + bytes.fromhex(m.group(4).decode()))
    rec_h = m.group(2).decode()

    sent = to_epoch(rec["sent_at"]) if rec["sent_at"] else None
    lo = int((sent if sent else rec["wire_epoch"]) - 120)
    hi = int((rec["wire_epoch"] or sent) + 30)
    secs = [s for s in range(lo, hi + 1) if sg.make_header(s) == blob[:16]]
    r["L3"] = len(secs) == 1
    r["L3_secs"] = secs

    kinds = ([KIND_MAP[rec["endpoint"]]]
             if rec["endpoint"] in KIND_MAP else INFO_CANDIDATES)
    hit = None
    for kind in kinds:
        claims = sg.build_claims(kind, rec["params"],
                                 client_sdk=rec["client_sdk"])
        if sg.commitment_digest(claims, nonce12).hex().upper() == rec_h:
            hit = (kind, claims)
            break
    r["L4"] = hit is not None
    r["L4_kind"] = hit[0] if hit else None
    r["L5"] = bool(hit) and len(secs) == 1 and sg.sign(
        secs[0], nonce12, hit[1]).hex().upper() == rec["sig"]
    return r, nonce12, hit


def main(path):
    recs = carve(path)
    print("%s: %d signed adj7 requests\n" % (path, len(recs)))
    n = 0
    for rec in recs:
        r, _, _ = verify(rec)
        n += all(r[k] for k in ("L0", "L1", "L2", "L3", "L4", "L5"))
        print("sid %-3s %-20s %s  L1=%s L2=%s L3=%s(%s) L4=%s(%s) "
              "BYTE-EXACT=%s"
              % (r["sid"], r["endpoint"], rec["method"], r["L1"], r["L2"],
                 r["L3"], r.get("L3_secs"), r["L4"], r.get("L4_kind"),
                 r["L5"]))
        kv = rec["auth_kv"]
        print("     %s headers_id=%s native=%s sdk=%s"
              % (kv.get("algorithm"), kv.get("headers_id"),
                 kv.get("native_version"), rec["client_sdk"]))
    print("\n%d/%d all-layers byte-exact" % (n, len(recs)))
    return 0 if n == len(recs) else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python run_verify.py <capture.saz>")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
