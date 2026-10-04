#!/usr/bin/env python3
"""_sub_alg_data.py — load _sub_ios_timing.json, extract the 28 distinct
16-byte headers = FIRST 16 BYTES OF THE DECODED SIGNATURE (256 b64 chars =
192 bytes; header16_hex field is a constant verification blob, not the
per-request header). Parse 4 BE uint32 words + LE variant, attach candidate
signing seconds. Saves _sub_alg_headers.json for the other _sub_alg_* scripts.
Pure local analysis, read-only on source.
"""
import json, os, base64

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "_sub_ios_timing.json")
OUT = os.path.join(HERE, "_sub_alg_headers.json")

def main():
    d = json.load(open(SRC))
    reqs = d["requests"]
    recs = []
    for r in reqs:
        sig = base64.b64decode(r["authorization"]["signature_b64"])
        assert len(sig) == 192
        head = sig[:16]
        words_be = [int.from_bytes(head[i:i+4], "big") for i in range(0, 16, 4)]
        words_le = [int.from_bytes(head[i:i+4], "little") for i in range(0, 16, 4)]
        rec = {
            "sid": r["sid"],
            "file": r["file"],
            "kind": r["kind"],
            "host": r["host"],
            "header16_hex": head.hex(),
            "w": words_be,
            "w_le": words_le,
            "cc": r["timers_unix"]["ClientConnected"],
            "cb": r["timers_unix"]["ClientBeginRequest"],
            "sec_min": r["signing_seconds"]["min"],
            "sec_max": r["signing_seconds"]["max"],
            "sec_candidates": r["signing_seconds"]["candidates"],
        }
        recs.append(rec)

    n_bad = sum(1 for x in recs for w in x["w"] if w >= (1 << 31))
    n_bad_le = sum(1 for x in recs for w in x["w_le"] if w >= (1 << 31))
    by_head = {}
    for x in recs:
        by_head.setdefault(x["header16_hex"], []).append(x)
    print(f"requests={len(recs)}  words_failing_31bit_law BE={n_bad} LE={n_bad_le}  "
          f"distinct_headers={len(by_head)}")

    for h, xs in by_head.items():
        wins = {(x["sec_min"], x["sec_max"]) for x in xs}
        if len(wins) > 1:
            print("WARN header seen in >1 second-window:", h[:16], wins)

    uniq = []
    for h, xs in sorted(by_head.items(), key=lambda kv: min(x["sec_min"] for x in kv[1])):
        secs = sorted({s for x in xs for s in x["sec_candidates"]})
        uniq.append({
            "header16_hex": h,
            "w": xs[0]["w"],
            "w_le": xs[0]["w_le"],
            "sec_min": min(x["sec_min"] for x in xs),
            "sec_max": max(x["sec_max"] for x in xs),
            "sec_candidates": secs,
            "sids": [x["sid"] for x in sorted(xs, key=lambda x: x["sid"])],
        })

    out = {"n_requests": len(recs), "n_headers": len(uniq), "headers": uniq,
           "requests": recs}
    json.dump(out, open(OUT, "w"), indent=1)
    print("wrote", OUT)

    print("\nidx  header16_hex                             w0..w3 (BE, dec)                    secs")
    for i, u in enumerate(uniq):
        print(f"{i:2d}  {u['header16_hex']}  {u['w']}  "
              f"[{u['sec_min']},{u['sec_max']}] sids={u['sids']}")

    # second-assignment ambiguity check: can each header be pinned to ONE second?
    multi = [(i, u["sec_candidates"]) for i, u in enumerate(uniq) if len(u["sec_candidates"]) > 1]
    print(f"\nheaders with >1 candidate second: {len(multi)}")
    for i, s in multi:
        print(f"  {i}: {s}")

if __name__ == "__main__":
    main()
