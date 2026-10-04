r"""click_selfv.py — mint each row with ITS OWN recovered V (not a fresh one).

region_invert.py was invalid: make_V_consistent() picks a FRESH V, so the
region is not reproducible from the second alone.  But d2 IS the seed and the
region law is  seed = V ^ (pid<<16),  so each row's exact V is recoverable:

    V = d2 ^ ((pid & 0xFFFF) << 16)

That means we can rebuild the row's own region deterministically and mint the
body without guessing.  The remaining unknown is the SIGNING SECOND, which
sets only the 16-byte Random3 header -- and we can invert that per blob.

So: for each row, rebuild region from its own V, mint at every recovered
second, and check the genuine blob set.  The control (session row 4) must
reproduce; if it does and clicks still do not, the click descriptors
themselves are wrong, not the second.
"""
from __future__ import annotations
import binascii, json, multiprocessing as mp, os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as MP
import F as Fmod

BLOBS = os.path.join(HERE, "_genuine_blobs.json")
SECS = os.path.join(HERE, "_blob_seconds.json")
SIGS = os.path.join(HERE, "all_signings.json")
OUT = os.path.join(HERE, "click_selfv_result.json")
WORKERS = int(os.environ.get("ADJ_WORKERS", "14"))

_G = {}


def _init():
    _G["MP"] = MP
    _G["F"] = Fmod
    _G["blobs"] = set(json.load(open(BLOBS)))


def _try(job):
    """Deprecated shim -- the real worker is _try2 (carries d8/d9 explicitly)."""
    return _try2((job[0], job[1], job[2], job[3], b"", job[4], job[5]))


def main():
    seconds = sorted(set(json.load(open(SECS)).values()))
    sig = json.load(open(SIGS))
    print("recovered seconds=%d workers=%d" % (len(seconds), WORKERS))

    # region sanity: does rebuilding from the row's own V reproduce its d0/d4?
    print("\n=== region self-consistency check ===")
    heads = {}
    for i, r in enumerate(sig):
        # d2 is the LITTLE-endian store of the seed, read back as a BE word,
        # so undo the byte flip before recovering V.
        seed = int.from_bytes(int(r["d2"], 16).to_bytes(4, "big"), "little")
        V = (seed ^ ((MP.DEFAULT_PID & 0xFFFF) << 16)) & 0xFFFFFFFF
        stored0 = binascii.unhexlify(r["d0"])
        chosen = None
        for name, head in (("HEAD_FIRST", Fmod.HEAD_FIRST),
                           ("HEAD_RESIGN", Fmod.HEAD_RESIGN)):
            d0w, _, _ = Fmod.region(V, MP.DEFAULT_PID, 0, head=head)
            if b"".join(w.to_bytes(4, "big") for w in d0w) == stored0:
                chosen = name
                break
        heads[i] = chosen
        kind = "click" if r["ev"] != 0 else "session"
        print("  row%-2d %-8s ev=%-6s  d0 rebuild OK via %s"
              % (i, kind, r["ev"], chosen))
        if chosen is None:
            print("      *** row %d region does not rebuild under either head"
                  % i)
            return 3

    results = []
    for i, r in enumerate(sig):
        kind = "click" if r["ev"] != 0 else "session"
        d0 = binascii.unhexlify(r["d0"])
        d2 = binascii.unhexlify(r["d2"])
        d4 = binascii.unhexlify(r["d4"])
        d8 = binascii.unhexlify(r["d8"])
        d9 = binascii.unhexlify(r["d9"])
        d7 = int(r["d7"], 16)
        d10 = binascii.unhexlify(r["d10"])
        # VA_ORDER remainder: #7 (d7), #10 (d10), #5, #1, #6, #3.
        # only d7 and d10 are stored per row; #5/#1/#6/#3 are the 4B fillers.
        others = [(4, 0, d7.to_bytes(4, "big")), (len(d10), 0, d10),
                  (4, 0, b"\x00\x00\x00\x00"), (4, 0, b"\x00\x00\x00\x00"),
                  (4, 0, b"\x00\x00\x00\x00"), (4, 0, b"\x00\x00\x00\x00")]
        head = (Fmod.HEAD_RESIGN if heads[i] == "HEAD_RESIGN"
                else Fmod.HEAD_FIRST)
        print("=== row %d %s ev=%s  head=%s ==="
              % (i, kind, r["ev"], heads[i]), flush=True)
        hit = None
        with mp.Pool(WORKERS, initializer=_init) as pool:
            for res in pool.imap_unordered(
                    _try2, [(d0, d2, d4, d8, d9, others, s, head)
                            for s in seconds], chunksize=1):
                if res:
                    hit = res
                    pool.terminate()
                    break
        if hit:
            print("   *** %s REPRODUCES at second=%d status=%s"
                  % (kind, hit[0], hit[2]))
        else:
            print("   %s: NO MATCH over %d seconds (with its OWN V)"
                  % (kind, len(seconds)))
        results.append({"row": i, "kind": kind, "ev": r["ev"],
                        "match": bool(hit), "second": hit[0] if hit else None})
        json.dump(results, open(OUT, "w"), indent=1)

    print("\n=== VERDICT ===")
    for x in results:
        print("  row%-2d %-8s ev=%-6s : %s"
              % (x["row"], x["kind"], x["ev"],
                 "REPRODUCES @%d" % x["second"] if x["match"] else "NO MATCH"))
    json.dump(results, open(OUT, "w"), indent=1)
    return 0


def _try2(job):
    row_d0, row_d2, row_d4, d8, d9, others, sec, head = job
    # d2 is the LE store of the seed read as BE -> flip back, then V = seed ^ pid<<16
    seed = int.from_bytes(int.from_bytes(row_d2, "big").to_bytes(4, "big"),
                          "little")
    V = (seed ^ ((MP.DEFAULT_PID & 0xFFFF) << 16)) & 0xFFFFFFFF
    d0w, d2w, d4w = Fmod.region(V, MP.DEFAULT_PID, 0, head=head)
    d0b = b"".join(w.to_bytes(4, "big") for w in d0w)
    d2b = struct.pack(">I", d2w)
    d4b = b"".join(w.to_bytes(4, "big") for w in d4w)
    descs = [(len(d0b), 0, d0b), (len(d9), 0, d9), (len(d8), 0, d8),
             (len(d4b), 0, d4b), (len(d2b), 0, d2b)] + others
    try:
        blob, vm = MP.finex_mint(descs, sec, max_steps=20_000_000)
    except Exception:
        return None
    h = blob.hex()
    return (sec, h, vm.get("status")) if h in _G["blobs"] else None


if __name__ == "__main__":
    raise SystemExit(main())
