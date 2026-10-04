"""Given a measured region->body model for a golden, solve the golden body,
then verify the recovered region against F.py's materializer and brute-force
the fill instant (tv_usec, pid) that produced the seed.
"""
import base64, json, os, re, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M
import bodymodel as BM
import F as FR
from _g12 import golden_body, base_dmap, patch_region, NAMES, KIND, SEC

ZW144, Z, ZW32 = bytes(144), bytes(4), bytes(32)


def main():
    tag = sys.argv[1]
    m = BM.Model.from_raw(json.load(open(
        os.path.join(HERE, "_g12_%s.json" % tag))), KIND[tag])
    print("model rank", m.rank)
    body, _h = golden_body(tag)
    sol = m.solve(body)
    if sol is None:
        print(tag, "SOLVE INCONSISTENT -- body is NOT a function of the region")
        print("   with these non-region descriptors")
        return
    sol.pop("_rank")
    print(tag, "SOLVE CONSISTENT. recovered region words:")
    for k in NAMES:
        print("   %-4s %08x" % (k, sol[k]))
    print("  predict match:", m.predict(sol) == body)

    # ---- F.py structural verification -------------------------------------
    seed = int.from_bytes(struct.pack(">I", sol["S"]), "little")
    print("  seed = %08x" % seed)
    d4w = FR._d4_words(seed)
    print("  F d4 :", ["%08x" % v for v in d4w])
    print("  rec d4:", ["%08x" % sol[k] for k in ("F4", "F5", "F6")])
    print("  F_match_d4:", d4w[4] == sol["F4"])
    d0c = FR._d0_words(d4w, head=M.DEVICE_SELECTORS)
    print("  F_match_d0 (words2,3):",
          d0c[2] == sol["T0"] and d0c[3] == sol["T1"],
          ["%08x" % v for v in (d0c[2], d0c[3])],
          ["%08x" % v for v in (sol["T0"], sol["T1"])])
    for name, head in (("HEAD_FIRST", FR.HEAD_FIRST),
                       ("HEAD_RESIGN", FR.HEAD_RESIGN),
                       ("HEAD_RESIGN_ALT", FR.HEAD_RESIGN_ALT)):
        w = FR._d0_words(d4w, head=head)
        print("   head %-16s d0[2:4]=%s  match=%s"
              % (name, ["%08x" % v for v in w[2:4]],
                 w[2] == sol["T0"] and w[3] == sol["T1"]))

    # ---- brute force (pid, tv_usec) --------------------------------------
    sec = SEC[tag]
    hits = []
    for pid in range(1 << 16):
        V = seed ^ (pid << 16)
        usec = V ^ sec
        if usec < 1000000:
            hits.append((pid, usec))
    print("  fill-instant candidates (pid, tv_usec):", len(hits),
          hits[:12])


if __name__ == "__main__":
    main()
