"""fit_batch.py - run a batch of fit_gen dumps in parallel worker processes.

Each run takes ~60-130 s of Unicorn CPU, so we fan out over processes.
Outputs are the tiny JSONs from fit_gen.py (three region buffers only).
"""
import json
import multiprocessing as mp
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "fit_runs")


def job(spec):
    import fit_gen
    tag = spec["tag"]
    cfg = spec.get("cfg", {})
    path = os.path.join(OUT, tag + ".json")
    if os.path.exists(path):
        return (tag, "skip(exists)")
    try:
        rec = fit_gen.run_one(cfg, path)
        return (tag, "ok V=%08x match=%s" % (rec["V"], rec["node_va_match"]))
    except Exception as ex:  # noqa
        return (tag, "ERR %r" % (ex,))


def main():
    specs = json.load(open(sys.argv[1]))
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    os.makedirs(OUT, exist_ok=True)
    with mp.Pool(n) as pool:
        for tag, msg in pool.imap_unordered(job, specs):
            print("%-16s %s" % (tag, msg), flush=True)


if __name__ == "__main__":
    main()
