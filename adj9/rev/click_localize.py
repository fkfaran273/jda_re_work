r"""click_localize.py — localize WHERE the click envelope diverges.

Facts established:
  * session envelope reproduces byte-exact (control row 4, second 1789240075)
  * click envelopes do NOT reproduce over all 274 recovered seconds
  * descriptor assembly shape is identical for both (9 descs)
  * so the divergence is in descriptor CONTENT, not layout or VM

This compares, field by field, a genuine click descriptor row against a
genuine session descriptor row and against what OUR signer produces for the
same kind.  Specifically it checks the things that could differ for clicks
only:
    d7  (unpadded desc10 length)   -- we force 388; genuine click rows differ
    d8  (the 16B constant)         -- confirmed constant
    d9  (cert SHA-1)              -- must equal across kinds
    d10 (claim string)            -- the click claim law
    d0/d2/d4 (region)             -- pure fn of second, so equal by construction
and then mints both kinds at the SAME second to see whether the divergence is
in the body or only in the descriptor inputs.
"""
from __future__ import annotations
import binascii, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as MP

SIGS = os.path.join(HERE, "all_signings.json")
CTRL_SECOND = 1789240075


def show(tag, row):
    d10 = binascii.unhexlify(row["d10"])
    print("--- %s  ev=%s" % (tag, row["ev"]))
    for k in ("d0", "d2", "d4", "d7", "d8", "d9"):
        if k in row:
            print("    %-3s = %s" % (k, row[k][:72]))
    print("    d10 = %d bytes (unpadded %d)"
          % (len(d10), int(row["d7"], 16)))
    return d10


def main():
    sig = json.load(open(SIGS))
    print("=== genuine descriptor rows ===")
    sess = show("SESSION row4 (reproduces)", sig[4])
    clicks = {}
    for i, r in enumerate(sig):
        if r["ev"] != 0:
            clicks[i] = show("CLICK row%d" % i, r)

    print("\n=== cross-kind descriptor comparison ===")
    for k in ("d8", "d9"):
        vals = {r[k] for r in sig if k in r}
        print("  %s distinct across ALL rows: %d  %s"
              % (k, len(vals), list(vals)[:2]))
    print("  d7 by kind:")
    for i, r in enumerate(sig):
        print("    row%-2d ev=%-6s d7=%s (=%d)  d10=%dB"
              % (i, r["ev"], r["d7"], int(r["d7"], 16), len(r["d10"]) // 2))

    print("\n=== what OUR law says the lengths should be ===")
    for kind in ("session", "click"):
        keys = MP.desc10_keys(kind, {})
        print("  %-11s claims=%d  (region/VM identical to the session case)"
              % (kind, len(keys)))

    print("\n=== mint both kinds at the SAME known-good second ===")
    sess_descs = [(len(sig[4]["d%d" % t]) // 2, 0,
                   binascii.unhexlify(sig[4]["d%d" % t]))
                  for t in MP.VA_ORDER if "d%d" % t in sig[4]]
    b, vm = MP.finex_mint(sess_descs, CTRL_SECOND, max_steps=20_000_000)
    print("  session mint @%d -> status=%s len=%d" % (CTRL_SECOND,
                                                      vm.get("status"), len(b)))
    blobs = set(json.load(open(os.path.join(HERE, "_genuine_blobs.json"))))
    print("  session blob in genuine set:", b.hex() in blobs)

    for i, r in sig.items() if isinstance(sig, dict) else []:
        pass
    for idx, r in enumerate(sig):
        if r["ev"] == 0:
            continue
        descs = [(len(r["d%d" % t]) // 2, 0, binascii.unhexlify(r["d%d" % t]))
                 for t in MP.VA_ORDER if "d%d" % t in r]
        b2, vm2 = MP.finex_mint(descs, CTRL_SECOND, max_steps=20_000_000)
        print("  click row%d mint @%d -> status=%s  in-blob-set=%s"
              % (idx, CTRL_SECOND, vm2.get("status"), b2.hex() in blobs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
