"""taint44.py — differential taint probe over the 48 transmitted dwords.

Question: which dwords of the blob depend on the server-UNKNOWN inputs
(#0 core record 36 dw, H 8 dw, #2 1 dw) vs only on server-KNOWN inputs
(claims, cert, constants)?

Method: run the 48/48-validated simulator (fin_vm2.FinEx) with everything
fixed except ONE input per variant; diff the slot-0 output window [0..48)
against the baseline. Header positions [0..4) must be unchanged in every
variant (they come from Random3(second) only) — built-in method sanity.

Classification of body dwords [4..48):
    UNKNOWN-tainted : moved under any unknown-input probe  -> server cannot
                      strictly verify (value free on their side)
    known-only      : moved only under the claims probe      -> server can
                      strictly verify via its own re-simulation
    static          : never moved                           -> constant /
                      structural

One-sided caveat: "did not move" under a random probe is evidence of
independence, not proof; two independent #0 probes reduce coincidence.
"""
import json, os, random, struct, sys, time
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx

D = json.load(open(os.path.join(HERE, "fin_descs.json")))
SEED = D["target"]["second"]
BLOB = bytes.fromhex(D["target"]["blob_hex"])
S0 = 0x5500000000                     # slot-0 stream = output window

BASE_DESCS = [(d["len_dw"], 0, bytes.fromhex(d["data_hex"])) for d in D["descs"]]
IDX = {d["build_idx"]: i for i, d in enumerate(D["descs"])}

# build_idx: 0 = #0 core record (36 dw), 2 = #2 (1 dw), 4 = #4 H (8 dw),
#            10 = #10 claims blob (90 dw)
VARIANTS = [
    ("base",    0,   []),
    ("core0_A", 101, [(0, "rand")]),
    ("core0_B", 202, [(0, "rand")]),
    ("H_rand",  303, [(4, "rand")]),
    ("s2_rand", 404, [(2, "rand")]),
    ("claims",  0,   [(10, "swap")]),
]


def run_variant(job):
    name, rng_seed, mut = job
    rng = random.Random(rng_seed)
    descs = [list(t) for t in BASE_DESCS]
    for bi, mode in mut:
        i = IDX[bi]
        len_dw, tag, data = descs[i]
        if mode == "rand":
            data = b"".join(struct.pack(">I", rng.getrandbits(32))
                            for _ in range(len_dw))
        elif mode == "swap":                 # device_name, equal length
            data = data.replace(b"moto g42", b"moto g43")
        descs[i][2] = data
    t0 = time.time()
    ex = FinEx(SEED, [tuple(t) for t in descs])
    status = ex.run(max_steps=12_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    sig = b"".join(struct.pack(">I", out.get((S0, k), 0)) for k in range(48))
    return name, status, ex.steps, time.time() - t0, sig.hex()


def main():
    with Pool(3) as p:
        res = p.map(run_variant, VARIANTS)
    sigs, meta = {}, {}
    for name, status, steps, dt, hexs in res:
        sigs[name] = hexs
        meta[name] = [status, steps, round(dt, 1)]
        print("%-9s %-11s steps=%9d  %5.1fs" % (name, status, steps, dt))
    base = bytes.fromhex(sigs["base"])
    print("baseline == captured blob :", base == BLOB)

    unk = ["core0_A", "core0_B", "H_rand", "s2_rand"]
    names = [v[0] for v in VARIANTS if v[0] != "base"]
    rows = []
    for k in range(48):
        b4 = base[4 * k:4 * k + 4]
        ch = [n for n in names if bytes.fromhex(sigs[n])[4 * k:4 * k + 4] != b4]
        if k < 4:
            cls = "header"
        elif any(n in ch for n in unk):
            cls = "UNKNOWN-tainted"
        elif "claims" in ch:
            cls = "known-only"
        else:
            cls = "static"
        rows.append([k, cls, ch])

    from collections import Counter
    print()
    for k, cls, ch in rows:
        print("dw %2d  %-15s %s" % (k, cls, ",".join(ch) if ch else "-"))
    summary = dict(Counter(cls for _, cls, _ in rows))
    print()
    print("summary:", summary)
    json.dump({"sigs": sigs, "meta": meta, "rows": rows, "summary": summary},
              open(os.path.join(HERE, "taint44_out.json"), "w"), indent=1)
    print("saved taint44_out.json")


if __name__ == "__main__":
    main()
