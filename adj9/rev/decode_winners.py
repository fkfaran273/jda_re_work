"""decode_winners.py — decode the 6 genuine winning blobs from win_capture.

For each capture: invert the header for the second, measure the body model
for (claims, second) at the ZERO-region baseline, solve the GF(2) system, and
re-mint the recovered region to check all 192 bytes.
"""
import json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import bodymodel as BM
import decoder as D

WINNERS = [int(x) for x in (sys.argv[1:] or ["0", "1", "2", "3", "4", "5"])]
WORKERS = int(os.environ.get("ADJ_WORKERS", "16"))


def main():
    rows = D.claims_from_capture()
    out = {}
    path = os.path.join(HERE, "decoder_winners.json")
    if os.path.exists(path):
        out = {int(k): v for k, v in json.load(open(path)).items()}
    for i in WINNERS:
        if i in out:
            continue
        claims, blob = rows[i]
        sec = D.find_second(blob, 1790341400, 1790341600)
        kind = claims.get("activity_kind", "session")
        print("=== winner %d  kind=%s second=%s" % (i, kind, sec))
        sys.stdout.flush()
        t0 = time.time()
        model = BM.Model.measure(sec, base_descs=None, claims=claims,
                                 kind=kind, nsamp=256, workers=WORKERS,
                                 sample_seed=D.SAMPLE_SEED + 1000 * i,
                                 cache=os.path.join(HERE, "cache_win%d.json" % i),
                                 progress=True)
        print("    model built in %.0fs rank=%s" % (time.time() - t0, model.rank))
        sys.stdout.flush()
        sol, seed, rep = D.decode(blob, model, kind=kind, claims=claims)
        for k, v in rep.items():
            print("    %-18s %s" % (k, v))
        out[i] = {"second": sec, "kind": kind, "report": rep, "words": sol,
                  "seed": seed, "claims": claims, "blob": blob.hex()}
        json.dump({str(k): v for k, v in out.items()}, open(path, "w"),
                  default=str)
        sys.stdout.flush()
    print("wrote decoder_winners.json")


if __name__ == "__main__":
    main()
