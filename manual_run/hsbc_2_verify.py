"""hsbc_2_verify.py -- tasks 1-4 on the HSBC 16 Oct capture.

1. header law:   make_header(sec) == blob[:16], sec searched around created_at
2. decode:       record layout + cert SHA-1 hex
3. head phase:   permutations of range(0x20,0x50), k=1..3, head16_for==head16
4. block law:    P.record_block(head, seed, claims(field map, our law), cert)
                 vs the blob's own rec[46:78]
Offline only.
"""
import itertools
import sys

import hsbc_lib as L
import adj9_decode as D
import adj9_pure as P


def find_second(ts_strings, blob):
    base_c = L.ts_to_unix(ts_strings["created_at"])
    base_s = L.ts_to_unix(ts_strings["sent_at"])
    seen = set()
    for base in (base_c, base_s):
        for d in range(-600, 601):
            s = base + d
            if s in seen:
                continue
            seen.add(s)
            if P.make_header(s) == blob[:16]:
                return s
    return None


def find_phase(seed, head16):
    rng = range(0x20, 0x50)
    for k in (1, 2, 3):
        for ph in itertools.permutations(rng, k):
            if P.head16_for(seed, ph) == head16:
                return ph
    return None


def main():
    for sid in ("07", "08", "09"):
        e = L.parse_entry(sid)
        kind, blob, f, env = e["kind"], e["blob"], e["fields"], e["env"]
        print("=" * 72)
        print("%s / %s  (%s, %d bytes blob)  SDK %s" %
              (sid, kind, e["method"], len(blob), e["client_sdk"]))
        print("  envelope:", {k: v for k, v in env.items()})

        # -- 1. header law ---------------------------------------------------
        sec = find_second({k: f[k] for k in ("created_at", "sent_at") if k in f},
                          blob)
        print("  [1] header law: second=%s  (created_at %s)" %
              (sec, f.get("created_at", "-")))
        if sec is None:
            print("      STOP: no second found")
            continue

        # -- 2. decode -------------------------------------------------------
        rec = D.whiten_body_inverse(blob[16:160], blob[:16])
        seed = int.from_bytes(rec[20:24], "big")
        head, cert, blk = rec[3:19], rec[25:45], rec[46:78]
        layout_ok = (rec[0:3] == b"\x01\x00\x08" and rec[19] == 2
                     and rec[24] == 3 and rec[45] == 4 and rec[78] == 5
                     and rec[111:114] == b"\x06\x01\x07"
                     and rec[130:144] == b"\x0e" * 14)
        print("  [2] record: seed=%08x  cert=%s" % (seed, cert.hex()))
        print("      layout fixed-bytes match our layout: %s" % layout_ok)
        if not layout_ok:
            print("      rec dump  :", rec.hex())
            for name, sl, want in (("magic", slice(0, 3), b"\x01\x00\x08"),
                                   ("tag19", 19, 2), ("tag24", 24, 3),
                                   ("tag45", 45, 4), ("tag78", 78, 5),
                                   ("tail111", slice(111, 114), b"\x06\x01\x07")):
                got = rec[sl]
                print("        %-8s got=%s want=%s %s" %
                      (name, got.hex() if isinstance(got, bytes) else got,
                       want.hex() if isinstance(want, bytes) else want,
                       "OK" if got == want else "DIFF"))
            print("        rec[78:111] sha-empty%ssha256('') == rec[79:111]: %s"
                  % ("", P.SHA0 == rec[79:111]))

        # -- 3. head phase ----------------------------------------------------
        ph = find_phase(seed, head)
        print("  [3] head phase:", ph, "(default (0x2b,))" if ph == (0x2B,) else "")

        # -- 4. block law ------------------------------------------------------
        val = dict(f)
        val.update({"activity_kind": kind, "client_sdk": e["client_sdk"],
                    "adj_signing_id": env["adj_signing_id"],
                    "headers_id": env["headers_id"],
                    "native_version": env["native_version"],
                    "adj_verification": env["adj_verification"]})
        order = P.claim_key_order(val, kind)
        print("  [4] our-law key order (%d keys): %s" % (len(order), order))
        present = [k for k in order if val.get(k)]
        absent = [k for k in order if not val.get(k)]
        padded, n = P.claims_padded(val, kind)
        got = P.record_block(head, seed, padded[:n], cert)
        print("      block vs our law: %s" %
              ("MATCH" if got == blk else "MISMATCH"))
        print("      keys in map but unused by law:",
              sorted(set(f) - set(order)))
        print("      law keys absent:", absent)
        print("      claims string (repr, %d chars): %r" %
              (n, "".join(val[k] for k in present)[:400]))


if __name__ == "__main__":
    main()
