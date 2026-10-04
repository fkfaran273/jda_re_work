r"""region_invert.py — is the click "NO MATCH" a real bug, or a corpus gap?

click_proof.py proved the click envelope does not reproduce, but only if the
click's true signing second is among the 274 recovered seconds.  The region
descriptors (#0/#2/#4) are a PURE function of the second (F.region), so we
can invert them with arithmetic -- no 15-second VM mint required.

If a click row's (d0,d2,d4) matches the region of some recovered second, the
click IS in the corpus and its failure to reproduce is a genuine bug.
If NO recovered second produces that region, the click's signing second is
absent from our blob set entirely, and "no match" proves nothing about our
signer -- it would be a corpus gap, exactly the trap the earlier control-less
sweep fell into.
"""
from __future__ import annotations
import binascii, json, os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as MP
import F as Fmod

SIGS = os.path.join(HERE, "all_signings.json")
SECS = os.path.join(HERE, "_blob_seconds.json")


def region_at(second):
    """d0/d2/d4 as our signer would build them for `second`."""
    V = MP.make_V_consistent(second, 928)
    pid = MP.DEFAULT_PID
    d0w, d2w, d4w = Fmod.region(V, pid, 0, head=Fmod.HEAD_FIRST)
    d0b = b"".join(w.to_bytes(4, "big") for w in d0w)
    d2b = struct.pack(">I", d2w)
    d4b = b"".join(w.to_bytes(4, "big") for w in d4w)
    return d0b, d2b, d4b


def main():
    sig = json.load(open(SIGS))
    seconds = sorted(set(json.load(open(SECS)).values()))
    print("recovered seconds: %d  (span %d..%d)"
          % (len(seconds), seconds[0], seconds[-1]))

    # Build the region signature for every recovered second ONCE.
    table = {}
    for s in seconds:
        d0, d2, d4 = region_at(s)
        table[(d0[:16], d2, d4)] = s
    print("region table built: %d entries" % len(table))

    print("\n=== which rows are IN the corpus? ===")
    for i, r in enumerate(sig):
        d0 = binascii.unhexlify(r["d0"])
        d2 = binascii.unhexlify(r["d2"])
        d4 = binascii.unhexlify(r["d4"])
        kind = "click" if r["ev"] != 0 else "session"
        hit = table.get((d0[:16], d2, d4))
        # also try without the d0 truncation, in case head phase differs
        hit2 = None
        if hit is None:
            for (k0, k2, k4), s in table.items():
                if k2 == d2 and k4 == d4 and k0 == d0[:16]:
                    hit2 = s
        got = hit if hit is not None else hit2
        print("  row%-2d %-8s ev=%-6s region-in-corpus: %s"
              % (i, kind, r["ev"],
                 ("YES second=%d" % got) if got else "NO"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
