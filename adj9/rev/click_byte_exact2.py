r"""click_byte_exact2.py — mint clicks at the ALREADY-RECOVERED signing seconds.

We have 274 genuine blob->second pairs from the header inversion.  Rather than
brute force, mint each click descriptor row at each recovered second and check
for a hit in the genuine blob set.  This is the missing proof: the 5 earlier
192-byte matches were all ev=0 sessions; the click envelope was never verified.
"""
from __future__ import annotations
import binascii, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as MP

OUT = os.path.join(HERE, "click_byte_exact_result.json")


def main():
    blobs = set(json.load(open(os.path.join(HERE, "_genuine_blobs.json"))))
    secs = sorted(set(json.load(open(os.path.join(HERE, "_blob_seconds.json"))).values()))
    sig = json.load(open(os.path.join(HERE, "all_signings.json")))
    click_rows = [r for r in sig if r["ev"] != "0"]
    print("blobs=%d seconds=%d click_rows=%d" % (len(blobs), len(secs), len(click_rows)))
    results = []
    for ri, r in enumerate(click_rows):
        descs = []
        for tag in MP.VA_ORDER:
            key = "d%d" % tag
            if key in r:
                descs.append((len(r[key]) // 2, 0, binascii.unhexlify(r[key])))
        print("=== row ev=%s descs=%d lens=%s" % (r["ev"], len(descs), [d[0] for d in descs]))
        sys.stdout.flush()
        hit = None
        for n, s in enumerate(secs):
            try:
                blob, vm = MP.finex_mint(descs, s, max_steps=20_000_000)
            except Exception:
                continue
            h = blob.hex()
            if h in blobs:
                hit = (s, h, vm.get("status"))
                print("   *** BYTE-EXACT MATCH second=%d status=%s" % (s, vm.get("status")))
                print("       %s" % h)
                break
            if n % 25 == 0:
                print("   ...tried %d/%d seconds" % (n, len(secs)), flush=True)
        results.append({"ev": r["ev"], "match": bool(hit),
                        "second": hit[0] if hit else None,
                        "blob": hit[1] if hit else None})
        json.dump(results, open(OUT, "w"), indent=1)
        if not hit:
            print("   NO MATCH across %d recovered seconds" % len(secs))
    print("\n=== SUMMARY ===")
    for x in results:
        print("  ev=%-8s %s" % (x["ev"], "MATCH @%d" % x["second"] if x["match"] else "NO MATCH"))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
