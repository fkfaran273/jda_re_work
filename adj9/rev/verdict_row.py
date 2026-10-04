r"""verdict_row.py — sweep one all_signings row over every recovered second.

Each row is run in its OWN process so a Windows Pool crash on one row cannot
destroy the results of the others.  Rebuilds the row's own region from its own
recovered V (via d2), picks the head phase that reproduces the captured d0, then
mints the 192-byte body at each of the 274 recovered seconds and checks the
result against _genuine_blobs.json.

Usage:  python verdict_row.py <row> [workers] [outfile]
"""
from __future__ import annotations
import binascii, json, multiprocessing as mp, os, struct, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as MP
import F as Fmod

BLOBS = os.path.join(HERE, "_genuine_blobs.json")
SECS = os.path.join(HERE, "_blob_seconds.json")
SIGS = os.path.join(HERE, "all_signings.json")

_G = {}


def _init():
    _G["blobs"] = set(json.load(open(BLOBS)))


def _try2(job):
    """Byte-identical to click_selfv._try2: rebuild region from row's own V."""
    row_d0, row_d2, row_d4, d8, d9, others, sec, head = job
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


def build_row(i, sig):
    r = sig[i]
    d2 = binascii.unhexlify(r["d2"])
    d8 = binascii.unhexlify(r["d8"])
    d9 = binascii.unhexlify(r["d9"])
    d7 = int(r["d7"], 16)
    d10 = binascii.unhexlify(r["d10"])
    stored0 = binascii.unhexlify(r["d0"])
    stored4 = binascii.unhexlify(r["d4"])

    seed = int.from_bytes(d2, "little")
    V = (seed ^ ((MP.DEFAULT_PID & 0xFFFF) << 16)) & 0xFFFFFFFF

    head = None
    for name, h in (("HEAD_FIRST", Fmod.HEAD_FIRST),
                    ("HEAD_RESIGN", Fmod.HEAD_RESIGN)):
        d0w, _, _ = Fmod.region(V, MP.DEFAULT_PID, 0, head=h)
        if b"".join(w.to_bytes(4, "big") for w in d0w) == stored0:
            head = h
            headname = name
            break
    if head is None:
        return None, None, None, None, None, None, None

    # confirm d4 too (independent of the head phase)
    _, _, d4w = Fmod.region(V, MP.DEFAULT_PID, 0, head=head)
    d4ok = b"".join(w.to_bytes(4, "big") for w in d4w) == stored4

    others = [(4, 0, d7.to_bytes(4, "big")), (len(d10), 0, d10),
              (4, 0, b"\0" * 4), (4, 0, b"\0" * 4),
              (4, 0, b"\0" * 4), (4, 0, b"\0" * 4)]
    return V, head, headname, d4ok, others, stored0, d2


def main():
    i = int(sys.argv[1])
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(
        HERE, "verdict_row%d.json" % i)

    seconds = sorted(set(json.load(open(SECS)).values()))
    sig = json.load(open(SIGS))
    r = sig[i]
    kind = "click" if r["ev"] != 0 else "session"

    V, head, headname, d4ok, others, stored0, d2 = build_row(i, sig)
    print("[row%d] kind=%s ev=%s V=0x%08x head=%s d4_rebuild_ok=%s"
          % (i, kind, r["ev"], V, headname, d4ok), flush=True)
    if head is None:
        json.dump({"row": i, "kind": kind, "ev": r["ev"], "error":
                   "region does not rebuild under either head"},
                  open(out, "w"), indent=1)
        return 3

    t0 = time.time()
    done = [0]
    hit = None
    try:
        with mp.Pool(workers, initializer=_init) as pool:
            for res in pool.imap_unordered(
                    _try2, [(stored0, d2, binascii.unhexlify(r["d4"]),
                             binascii.unhexlify(r["d8"]),
                             binascii.unhexlify(r["d9"]), others, s, head)
                            for s in seconds], chunksize=1):
                done[0] += 1
                if done[0] % 20 == 0:
                    print("[row%d] %d/%d swept  %.0fs"
                          % (i, done[0], len(seconds), time.time() - t0),
                          flush=True)
                if res:
                    hit = res
                    pool.terminate()
                    break
    except Exception as e:
        print("[row%d] POOL ERROR after %d/%d: %r"
              % (i, done[0], len(seconds), e), flush=True)

    res = {"row": i, "kind": kind, "ev": r["ev"], "head": headname,
           "V": "0x%08x" % V, "d4_rebuild_ok": d4ok,
           "swept": done[0], "seconds_total": len(seconds),
           "match": bool(hit), "second": hit[0] if hit else None,
           "status": hit[2] if hit else None,
           "blob": hit[1] if hit else None,
           "elapsed_s": round(time.time() - t0, 1),
           "complete": done[0] >= len(seconds)}
    json.dump(res, open(out, "w"), indent=1)
    print("[row%d] RESULT %s match=%s second=%s swept=%d/%d complete=%s "
          "elapsed=%.0fs"
          % (i, kind, bool(hit), hit[0] if hit else None, done[0],
             len(seconds), res["complete"], res["elapsed_s"]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
