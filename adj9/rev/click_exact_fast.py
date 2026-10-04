r"""click_exact_fast.py — byte-exact the CLICK envelope (the unproven one).

All 5 previously-proven 192-byte matches were ev=0 (session).  The click
envelope (ev=22272 / 23770 / 28663) was never verified.  We now know each
click's created_at epoch, and the signing second is within a small window of
it (the device signs at send time), so instead of brute-forcing 274 recovered
seconds we sweep only +/-N seconds around each click's own timestamp.
"""
from __future__ import annotations
import binascii, json, os, re, sys, datetime

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as MP

OUT = os.path.join(HERE, "click_exact_fast_result.json")
WINDOW = int(os.environ.get("ADJ_WINDOW", "90"))


def epoch_of(d10raw):
    m = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z[+-]\d{4})",
                  d10raw)
    if not m:
        return None
    return int(datetime.datetime.strptime(
        m.group(1), "%Y-%m-%dT%H:%M:%S.%fZ%z").timestamp())


def main():
    blobs = set(json.load(open(os.path.join(HERE, "_genuine_blobs.json"))))
    secs_map = json.load(open(os.path.join(HERE, "_blob_seconds.json")))
    sig = json.load(open(os.path.join(HERE, "all_signings.json")))
    results = []
    for r in sig:
        if r["ev"] == 0:
            continue
        raw = binascii.unhexlify(r["d10"]).decode("utf-8", "replace")
        ep = epoch_of(raw)
        descs = []
        for tag in MP.VA_ORDER:
            key = "d%d" % tag
            if key in r:
                descs.append((len(r[key]) // 2, 0, binascii.unhexlify(r[key])))
        print("=== ev=%s created_at_epoch=%s descs=%s" % (r["ev"], ep,
                                                         [d[0] for d in descs]))
        sys.stdout.flush()
        hit = None
        cands = range(ep - WINDOW, ep + WINDOW + 1)
        for n, s in enumerate(cands):
            # cheap pre-filter: the blob's first 16 bytes are make_header(s),
            # and the genuine blob must exist for that second.
            hdr = MP.make_header(s).hex()
            if not any(b.startswith(hdr) for b in blobs):
                continue
            try:
                blob, vm = MP.finex_mint(descs, s, max_steps=20_000_000)
            except Exception:
                continue
            h = blob.hex()
            if h in blobs:
                hit = (s, h, vm.get("status"))
                print("   *** BYTE-EXACT CLICK MATCH  second=%d status=%s" % (
                    s, vm.get("status")))
                print("       %s" % h)
                break
            if n % 25 == 0:
                print("   ...%d/%d" % (n, len(cands)), flush=True)
        if not hit:
            print("   NO MATCH in +/-%ds window" % WINDOW)
        results.append({"ev": r["ev"], "epoch": ep, "match": bool(hit),
                        "second": hit[0] if hit else None,
                        "blob": hit[1] if hit else None,
                        "status": hit[2] if hit else None})
        json.dump(results, open(OUT, "w"), indent=1)
    print("\n=== SUMMARY ===")
    for x in results:
        print("  ev=%-8s %s" % (x["ev"],
              "BYTE-EXACT @%d" % x["second"] if x["match"] else "NO MATCH"))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
