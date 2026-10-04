r"""clicks_only.py — finish the two remaining click rows (8, 9) of click_selfv.

The main run crashed on a Windows worker pipe error at row 7.  Rows 0-6 are
already done (5 sessions reproduce, row 2 does not).  This runs ONLY the
click rows, single worker pool size to avoid the WinError 5 handle crash.
"""
from __future__ import annotations
import binascii, json, multiprocessing as mp, os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as MP
import F as Fmod
from click_selfv import _init, _try2

BLOBS = os.path.join(HERE, "_genuine_blobs.json")
SECS = os.path.join(HERE, "_blob_seconds.json")
SIGS = os.path.join(HERE, "all_signings.json")
OUT = os.path.join(HERE, "clicks_only_result.json")
WORKERS = int(os.environ.get("ADJ_WORKERS", "6"))

WANT = [int(x) for x in (sys.argv[1:] or ["8", "9"])]


def main():
    seconds = sorted(set(json.load(open(SECS)).values()))
    sig = json.load(open(SIGS))
    results = []
    if os.path.exists(OUT):
        results = json.load(open(OUT))
    for i in WANT:
        r = sig[i]
        d0 = binascii.unhexlify(r["d0"]); d2 = binascii.unhexlify(r["d2"])
        d4 = binascii.unhexlify(r["d4"]); d8 = binascii.unhexlify(r["d8"])
        d9 = binascii.unhexlify(r["d9"])
        d7 = int(r["d7"], 16); d10 = binascii.unhexlify(r["d10"])
        seed = int.from_bytes(d2, "little")
        V = (seed ^ ((MP.DEFAULT_PID & 0xFFFF) << 16)) & 0xFFFFFFFF
        stored0 = binascii.unhexlify(r["d0"])
        head = Fmod.HEAD_FIRST
        for name, h in (("HEAD_FIRST", Fmod.HEAD_FIRST),
                        ("HEAD_RESIGN", Fmod.HEAD_RESIGN)):
            d0w, _, _ = Fmod.region(V, MP.DEFAULT_PID, 0, head=h)
            if b"".join(w.to_bytes(4, "big") for w in d0w) == stored0:
                head = h
                print("row%d head=%s" % (i, name), flush=True)
                break
        others = [(4, 0, d7.to_bytes(4, "big")), (len(d10), 0, d10),
                  (4, 0, b"\0" * 4), (4, 0, b"\0" * 4),
                  (4, 0, b"\0" * 4), (4, 0, b"\0" * 4)]
        print("=== row %d click ev=%s  (%d seconds) ===" % (i, r["ev"],
                                                           len(seconds)),
              flush=True)
        hit = None
        with mp.Pool(WORKERS, initializer=_init) as pool:
            for res in pool.imap_unordered(
                    _try2, [(d0, d2, d4, d8, d9, others, s, head)
                            for s in seconds], chunksize=1):
                if res:
                    hit = res; pool.terminate(); break
        if hit:
            print("   *** CLICK REPRODUCES at second=%d status=%s"
                  % (hit[0], hit[2]), flush=True)
        else:
            print("   click: NO MATCH over %d seconds" % len(seconds),
                  flush=True)
        results.append({"row": i, "kind": "click", "ev": r["ev"],
                        "match": bool(hit), "second": hit[0] if hit else None})
        json.dump(results, open(OUT, "w"), indent=1)
    print("\n=== DONE ===")
    for x in results:
        print("  row%d click ev=%-6s : %s"
              % (x["row"], x["ev"],
                 "REPRODUCES @%d" % x["second"] if x["match"] else "NO MATCH"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
