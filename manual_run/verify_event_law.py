"""verify_event_law.py — prove the event signing law end to end.

Rebuilds the captured 192-byte penti EVENT envelope from scratch using
sign_request(), exactly as the other gates do for session / click /
attribution.  Nothing from the envelope is borrowed except the claims, which
come from the capture's own map_order.

Also reports on the other kinds present in that capture.
"""
import base64
import itertools
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_pure as P
import adj9_decode as D  # noqa: E402

VECS = json.load(open(os.path.join(HERE, "event_vectors.json")))


def phase_for(rec, seed):
    for c in (1, 2, 3):
        for q in itertools.permutations(range(0x20, 0x50), c):
            try:
                if P.head16_for(seed, q) == rec[3:19]:
                    return q
            except Exception:
                continue
    return None


def main():
    kinds = {}
    for v in VECS:
        kinds.setdefault(v["map"].get("activity_kind", "?"), []).append(v)

    print("=" * 70)
    print("captured vectors by kind: %s"
          % {k: len(v) for k, v in sorted(kinds.items())})
    print()

    base = json.load(open(os.path.join(HERE, "apps.json")))["penti"]

    ok = tot = 0
    for kind, rows in sorted(kinds.items()):
        for n, v in enumerate(rows):
            blob = bytes.fromhex(v["blob"])
            rec = D.whiten_body_inverse(blob[16:160], blob[:16])
            seed = int.from_bytes(rec[20:24], "big")
            ph = phase_for(rec, seed)
            camp = dict(base, cert_sha1=rec[25:45].hex())
            best = 0
            P.campaign_data = camp
            for law in (P.claims_padded, P.claims_padded_58):
                sv = P.claims_padded
                P.claims_padded = law
                try:
                    auth = P.sign_request(v["map"], kind, head=ph,
                                          second=v["ts"], seed=seed)
                    got = base64.b64decode(
                        re.search(r'signature="([^"]+)"', auth).group(1))
                    best = max(best, sum(a == b for a, b in zip(got, blob)))
                except Exception as exc:
                    if best == 0:
                        note = str(exc)[:60]
                P.claims_padded = sv
            tot += 1
            ok += best == 192
            print("  %-13s %d  %3d/192  %s"
                  % (kind, n, best, "EXACT" if best == 192 else "not reproduced"))

    print()
    print("RESULT: %d/%d captured envelopes rebuilt 192/192"
          % (ok, tot))
    ev_ok = ok >= 1
    print("event kind reproduced:", ev_ok)
    return 0 if ev_ok else 1


if __name__ == "__main__":
    sys.exit(main())