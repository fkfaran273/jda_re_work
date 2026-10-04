r"""click_byte_exact.py — the missing proof: is our CLICK signature byte-exact?

All 5 previously-proven 192-byte matches were ev=0 (session).  The click
envelope (ev=22272 / 23770 / 28663) was never byte-verified.  This finds
genuine click blobs in the capture, inverts the Random3 header to recover
their signing second, re-mints the identical descriptor set at that second
with OUR VM, and diffs all 192 bytes.

If a click matches -> our click signature is proven too.
If none match  -> we have a real, unfound click-path bug.
"""
from __future__ import annotations
import binascii, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as MP

BLOBS = os.path.join(HERE, "_genuine_blobs.json")
OUT = os.path.join(HERE, "click_byte_exact_result.json")


def find_second(blobhex, lo, hi):
    """Invert make_header: the blob's first 16 bytes ARE make_header(second)."""
    target = blobhex[:32]
    for s in range(lo, hi):
        if MP.make_header(s).hex() == target:
            return s
    return None


def main():
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 1789043000
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 1789046000
    blobs = json.load(open(BLOBS))
    # genuine click descriptor rows (ev != 0)
    sig = json.load(open(os.path.join(HERE, "all_signings.json")))
    click_rows = [r for r in sig if r["ev"] != "0"]
    print("blobs=%d  click_rows=%d  window=%d..%d" % (
        len(blobs), len(click_rows), lo, hi))
    for r in click_rows:
        print("  ev=%s d10=%dB" % (r["ev"], len(r["d10"]) // 2))
    bset = set(blobs)
    results = []
    for r in click_rows:
        # rebuild the descriptor list in VA_ORDER from the stored row
        descs = []
        for tag in MP.VA_ORDER:
            key = "d%d" % tag
            if key not in r:
                continue
            hexs = r[key]
            nb = len(hexs) // 2
            descs.append((nb, 0, binascii.unhexlify(hexs)))
        print("row ev=%s descs=%d lens=%s" % (
            r["ev"], len(descs), [d[0] for d in descs]))
        sys.stdout.flush()
        # brute force the second for THIS descriptor set
        found = None
        for s in range(lo, hi):
            try:
                blob, vm = MP.finex_mint(descs, s, max_steps=20_000_000)
            except Exception:
                continue
            h = blob.hex()
            if h in bset:
                found = (s, h, vm.get("status"))
                break
            if (s - lo) % 20 == 0:
                print("   ...%d steps, no hit" % (s - lo), flush=True)
        if found:
            s, h, st = found
            print("   *** BYTE-EXACT MATCH at second=%d status=%s" % (s, st))
            print("       %s" % h[:80])
            results.append({"ev": r["ev"], "second": s, "status": st,
                            "match": True, "blob": h})
        else:
            print("   no genuine blob matched this descriptor set in window")
            results.append({"ev": r["ev"], "match": False})
        json.dump(results, open(OUT, "w"), indent=1)
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
