r"""click_proof.py — settle the click envelope question, with a real control.

The gap: 5 byte-exact 192B matches were ALL ev=0 (session).  The click rows
(ev=22272/23770/28663) were never byte-verified.  A previous sweep found no
click match, but its control was cut off, so the result meant nothing.

This time the control runs IN BAND: session row 4 (known byte-exact) is swept
with the identical code path.  Only if the control reproduces may a click
"NO MATCH" be believed.

Speed: the VM mint is ~15 s, so sweep the 274 recovered seconds across a
process pool.  Cheap pre-filter first -- the blob's first 16 bytes are
make_header(second), so only seconds whose header actually prefixes a known
genuine blob are worth minting.
"""
from __future__ import annotations
import binascii, json, multiprocessing as mp, os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as MP

BLOBS = os.path.join(HERE, "_genuine_blobs.json")
SECS = os.path.join(HERE, "_blob_seconds.json")
SIGS = os.path.join(HERE, "all_signings.json")
OUT = os.path.join(HERE, "click_proof_result.json")
WORKERS = int(os.environ.get("ADJ_WORKERS", "8"))

_G = {}


def _init():
    import mint_pipeline as m
    _G["MP"] = m
    _G["blobs"] = set(json.load(open(BLOBS)))


def _try(job):
    descs, sec = job
    try:
        blob, vm = _G["MP"].finex_mint(descs, sec, max_steps=20_000_000)
    except Exception as e:
        return None
    h = blob.hex()
    if h in _G["blobs"]:
        return (sec, h, vm.get("status"))
    return None


def sweep(descs, seconds, label):
    jobs = [(descs, s) for s in seconds]
    with mp.Pool(WORKERS, initializer=_init) as pool:
        for res in pool.imap_unordered(_try, jobs, chunksize=1):
            if res:
                pool.terminate()
                print("   *** %s BYTE-EXACT at second=%d status=%s"
                      % (label, res[0], res[2]), flush=True)
                return res
    print("   %s: no match over %d seconds" % (label, len(seconds)), flush=True)
    return None


def descs_of(row):
    out = []
    for tag in MP.VA_ORDER:
        k = "d%d" % tag
        if k in row:
            out.append((len(row[k]) // 2, 0, binascii.unhexlify(row[k])))
    return out


def main():
    blobs = json.load(open(BLOBS))
    seconds = sorted(set(json.load(open(SECS)).values()))
    # header pre-filter: keep only seconds whose header prefixes a real blob
    hdrs = {b[:32] for b in blobs}
    cand = [s for s in seconds if MP.make_header(s).hex() in hdrs]
    print("recovered seconds=%d  header-matching candidates=%d  workers=%d"
          % (len(seconds), len(cand), WORKERS))
    sig = json.load(open(SIGS))
    results = []

    # ---- CONTROL: session row 4, known byte-exact -------------------------
    ctrl = descs_of(sig[4])
    print("=== CONTROL session row 4 (ev=0) ===", flush=True)
    c = sweep(ctrl, cand, "CONTROL-session")
    results.append({"label": "CONTROL-session-row4", "ev": 0,
                    "match": bool(c), "second": c[0] if c else None})
    json.dump(results, open(OUT, "w"), indent=1)
    if not c:
        print("\n*** CONTROL FAILED -- click results would be meaningless."
              " Stopping.")
        return 2
    # derive the control's second and use it to sanity-check the method
    ctrl_second = c[0]

    # ---- the click rows ---------------------------------------------------
    for i, r in enumerate(sig):
        if r["ev"] == 0:
            continue
        print("=== row %d CLICK ev=%s ===" % (i, r["ev"]), flush=True)
        d = descs_of(r)
        res = sweep(d, cand, "CLICK-ev%s" % r["ev"])
        results.append({"label": "click-row%d" % i, "ev": r["ev"],
                        "match": bool(res), "second": res[0] if res else None,
                        "blob": res[1] if res else None})
        json.dump(results, open(OUT, "w"), indent=1)

    print("\n=== VERDICT ===")
    print("  CONTROL session reproduces : %s" % ("YES @%d" % ctrl_second))
    for x in results[1:]:
        print("  %-16s ev=%-6s : %s" % (
            x["label"], x["ev"],
            "BYTE-EXACT @%d" % x["second"] if x["match"] else "NO MATCH"))
    json.dump(results, open(OUT, "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
