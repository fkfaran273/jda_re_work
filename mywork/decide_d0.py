"""decide_d0.py — THE decisive d0 comparison, per genuine device signing.

For each real device signing in rows_full.json we have:
  * cap0  — the DEVICE's own descriptor #0 (foldhook_native, real com.penti.app)
  * S     — the seed the native itself reported

We then produce two candidate d0 for that SAME seed:
  * nat   — native_d0.posthead_region_native(S): the REAL libsigner nSign run
            under Unicorn (what adj9_signer.region/mint_blob actually ship)
  * f(h)  — F.region(S, 0, 0, h) for every candidate head h (the pure-Python
            model, what mint_pipeline.resolve_region ships)

The question that decides the Organic bug: does the thing we SHIP (nat) equal
the thing the DEVICE produced (cap0)?

  nat == cap0 for all rows  -> the shipping path is faithful; look elsewhere.
  nat != cap0 for all rows  -> the Unicorn "real signer" itself diverges from
                               the device in the d0 head phase, so every
                               offline mint ships a byte-wrong #0 (144 B).
                               The head that DOES match the device is then the
                               one to ship instead.

Run:  python decide_d0.py            (uses all rows; ~2 min per row)
"""
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "signer"))
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")

import F as Fmod                                            # noqa: E402
import mint_pipeline as MP                                  # noqa: E402
import native_d0                                            # noqa: E402

ROWS = os.path.join(HERE, "artifacts", "rows_full.json")
ALL_ROWS = os.path.join(HERE, "artifacts", "rows_full.json")
CACHE = os.path.join(HERE, "artifacts", "decide_d0_cache.json")


def be(ws):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in ws)


def load_cache():
    try:
        return json.load(open(CACHE, encoding="utf-8"))
    except Exception:
        return {}


def main():
    rows = [r for r in (json.load(open(ALL_ROWS, encoding="utf-8"))["rows"])
            if int(r.get("sign_id") or 0) <= 2]
    cache = load_cache()

    heads = [("F.HEAD_FIRST", Fmod.HEAD_FIRST),
             ("F.HEAD_RESIGN", Fmod.HEAD_RESIGN),
             ("SYNTH_FIRST", Fmod.SYNTH_HEAD_FIRST),
             ("SYNTH_RESIGN", Fmod.SYNTH_HEAD_RESIGN),
             ("DEVICE_SELECTORS", MP.DEVICE_SELECTORS),
             ("None", None)]
    # the re-sign phase prepends TWO selectors (0x2B, 0x07), shifting every
    # half-word by two; the X half-word therefore sits at d0 word 3, not 1.
    # Solve for that shifted head directly from the data (see region_replay_2x2
    # .py) instead of trusting a table nobody has re-verified since.
    heads.append(("RESIGN_x3_first", (0x2B, 0x07) + MP.DEVICE_SELECTORS[1:]))
    heads.append(("RESIGN_prefix_only", (0x2B, 0x07)))

    tally = {"nat_eq_cap0": 0, "nat_ne_cap0": 0}
    print("=" * 76)
    print("DECISIVE d0 COMPARISON  (device #0 vs what we actually ship)")
    print("=" * 76)

    for r in rows:
        S = int(r["S"])
        key = "%08x" % S
        cap0 = bytes.fromhex(r["desc"]["0"]["hex"])
        if key not in cache:
            print("  [%s] emulating native for seed 0x%s ... (this is the slow "
                  "part, ~2 min)" % (r.get("sign_id"), key), flush=True)
            t0 = time.time()
            nd0, _, _ = native_d0.posthead_region_native(S)
            cache[key] = [w for w in nd0]
            json.dump(cache, open(CACHE, "w", encoding="utf-8"), indent=1)
            print("      done in %.1fs" % (time.time() - t0), flush=True)
        nat = be(cache[key])

        ok = (nat == cap0)
        tally["nat_eq_cap0" if ok else "nat_ne_cap0"] += 1
        print("-" * 76)
        print("sign_id=%s seed=0x%s" % (r.get("sign_id"), key))
        print("  SHIPPED native d0 == DEVICE d0 : %s   (%d/144 bytes differ)"
              % ("YES" if ok else "NO",
                 sum(1 for a, b in zip(nat, cap0) if a != b)))
        hits = []
        for hname, h in heads:
            d0w, _, _ = Fmod.region(S, 0, 0, h)
            if be(d0w) == cap0:
                hits.append(hname)
        print("  F.region head that DOES match DEVICE: %s"
              % (", ".join(hits) if hits else "none"))
        if ok and not hits:
            print("     (native is right but no pure-Python head models it -> "
                  "keep shipping the native)")

    print("=" * 76)
    print("TALLY: shipped-native matches device on %d/%d signings; "
          "differs on %d/%d"
          % (tally["nat_eq_cap0"], len(rows), tally["nat_ne_cap0"], len(rows)))
    print("=" * 76)
    return 0


if __name__ == "__main__":
    sys.exit(main())
