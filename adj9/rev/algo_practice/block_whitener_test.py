"""block_whitener_test.py — is the block a second whitener pass?

The d0 head words are whitener halfwords: _selector_halfword((sel<<1)+3, src)
over the d4 source with a per-request selector schedule. If the 32-B block is
also 16 whitener halfwords (over the d4 source, or over another source), each
halfword must solve for some selector, and the schedule must be CONSISTENT
across all 6 genuine blobs. Test both sources and the consistency.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(HERE)
sys.path.insert(0, REV)
import F as FP  # noqa: E402


def solve_schedule(blocks, source_fn, max_sel=2048):
    """Try to solve one selector per 16-B halfword position, consistent
    across all samples. Returns (schedule or None, per-pos options)."""
    datas = [source_fn(w["S"]) for w in blocks]
    schedule = []
    for j in range(16):
        options = None
        for data, w in zip(datas, blocks):
            hv = int.from_bytes(w["block"][2 * j:2 * j + 2], "big")
            hits = set()
            for sel in range(max_sel):
                if FP._selector_halfword((sel << 1) + 3, data) == hv:
                    hits.add(sel)
            options = hits if options is None else (options & hits)
            if not options:
                break
        if not options:
            print("  halfword %d: NO consistent selector" % j)
            return None
        schedule.append(sorted(options))
        print("  halfword %2d: %d consistent selectors: %s"
              % (j, len(options), [hex(s) for s in sorted(options)[:6]]))
    return schedule


def main():
    wins = json.load(open(os.path.join(REV, "block_pattern_analysis.json")))
    blocks = wins["wins"]
    for w in blocks:
        if isinstance(w["block"], str):
            w["block"] = bytes.fromhex(w["block"])
    print("genuine blocks: %d" % len(blocks))

    print("\n== source: d4 whitener source ==")
    sched_d4 = solve_schedule(blocks, lambda S: FP._d0_source(FP._d4_words(S)))

    print("\n== source: d0 words themselves (36 words) ==")
    d0_datas = []
    for w in blocks:
        # d0 for the genuine rows is in the wins? reconstruct via head law is
        # unreliable; use the recorded head words if present, else skip
        d0_datas.append(None)
    # d0 source test needs the full d0; the wins only carry 'head' — skip
    # unless block_pattern stored d0. (blocks come from decoded records.)

    if sched_d4:
        print("\nD4-SOURCE SCHEDULE FOUND (options per position):")
        print(json.dumps([[hex(s) for s in opts] for opts in sched_d4]))


if __name__ == "__main__":
    main()
