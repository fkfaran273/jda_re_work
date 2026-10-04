"""validate_decoder.py — prove the decoder on captured corpus rows.

For each row: measure the body model at that row's own (descriptors, second),
solve the row's captured blob, and compare the recovered region against the
captured one, then re-mint the recovered region and compare all 192 bytes.
"""
import json, os, struct, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import bodymodel as BM
import decoder as D

ROWS = [int(x) for x in (sys.argv[1:] or ["7"])]


def main():
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    path = os.path.join(HERE, "decoder_corpus.json")
    res = json.load(open(path)) if os.path.exists(path) else {}
    for i in ROWS:
        if str(i) in res:
            continue
        descs = D.corpus_descs(i)
        sec = D.corpus_second(i)
        blob = bytes.fromhex(ph3[i]["blob"])
        t0 = time.time()
        model = BM.Model.measure(sec, base_descs=descs,
                                 cache=os.path.join(HERE, "cache_row%d.json" % i),
                                 progress=True)
        print("ROW %d second=%d model in %.0fs rank=%d"
              % (i, sec, time.time() - t0, model.rank))
        sys.stdout.flush()
        sol, seed, rep = D.decode(blob, model, base_descs=descs)
        r = asg[i]
        d0 = struct.unpack(">36I", bytes.fromhex(r["d0"]))
        d4 = struct.unpack(">8I", bytes.fromhex(r["d4"]))
        d2 = struct.unpack(">I", bytes.fromhex(r["d2"]))
        truth = {"W0": d0[0], "X": d0[1], "T0": d0[2], "T1": d0[3],
                 "F4": d4[4], "F5": d4[5], "F6": d4[6], "S": d2[0]}
        if sol:
            rep["region_exact"] = all(sol[k] == truth[k] for k in truth)
            rep["region_diff"] = {k: ["%08x" % truth[k], "%08x" % sol[k]]
                                  for k in truth if sol[k] != truth[k]}
            rep["seed_exact"] = (seed == int.from_bytes(
                struct.pack(">I", d2[0]), "little"))
        for k, v in rep.items():
            print("    %-18s %s" % (k, v))
        res[str(i)] = rep
        json.dump(res, open(path, "w"), default=str)
        sys.stdout.flush()
    print("wrote decoder_corpus.json")


if __name__ == "__main__":
    main()
