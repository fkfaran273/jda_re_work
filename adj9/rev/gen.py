"""gen.py — the generativity test for a decoded region.

F.py fills the region at a wall-clock instant:

    seed = V ^ (pid16 << 16),   V = second ^ (usec & 0xFFFFF),  0 <= pid16

so, given a recovered seed S and the true signing second s,

    S ^ s = pid16<<16 ^ usec     with 0 <= usec < 2**20
    =>  pid16 = ((S ^ s) >> 16) ^ (usec >> 16),   usec>>16 in 0..15
    =>  usec  = (S ^ s) & 0xFFFF  +  65536 * (usec >> 16)

A real device stamps created_at a few ms AFTER the fill, in the same Unix
second, so usec <= created_at_ms * 1000 — which usually pins (usec>>16) to
0 and leaves exactly ONE candidate pid16 per signing.  If the same pid16
survives for every signing, the region is generatively produced by
    S = (sec ^ usec) ^ (pid16 << 16)
and the whole 45-word region is synthesizable.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
IST = timezone(timedelta(hours=5, minutes=30))
CEST = timezone(timedelta(hours=2))


def created_at_ms(s):
    """'2026-09-25T18:35:08.025Z+0530' -> epoch milliseconds."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\.(\d+)Z([+-]\d{2})(\d{2})", s)
    if not m:
        return None
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=timezone.utc)
    off = timedelta(hours=int(m.group(3)), minutes=int(m.group(4)))
    return int((base - off).timestamp()) * 1000 + int(m.group(2))


def candidates(seed, second, ca_ms=None, slack_ms=0):
    """[(pid16, usec)] consistent with the seed and the signing second."""
    x = (seed ^ second) & 0xFFFFFFFF
    lo = x & 0xFFFF
    hi = x >> 16
    tmax = 15
    if ca_ms is not None:
        cap = (ca_ms + slack_ms) * 1000
        tmax = min(tmax, cap // 65536)
    out = []
    for t in range(tmax + 1):
        out.append((hi ^ t, lo + 65536 * t))
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        HERE, "decoder_winners.json")
    data = json.load(open(path))
    keys = sorted(data, key=lambda k: int(k))
    sets = []
    print("%-3s %-6s %-12s %-10s %-9s %-9s %s"
          % ("#", "kind", "second", "seed", "S^s>>16", "ca_ms", "pid16 (usec)"))
    for k in keys:
        e = data[k]
        if e.get("seed") in (None, "None"):
            print("%-3s  no seed" % k)
            continue
        seed = int(str(e["seed"]), 16)
        sec = int(e["second"])
        ca = (e.get("claims") or {}).get("created_at")
        ca_ms = created_at_ms(ca) if ca else None
        if ca_ms is not None and ca_ms // 1000 != sec:
            print("   note: created_at second %d != signing second %d"
                  % (ca_ms // 1000, sec))
        c = candidates(seed, sec, ca_ms)
        sets.append({p for p, _u in c})
        x = (seed ^ sec) & 0xFFFFFFFF
        print("%-3s %-6s %-12d %-10s %08x   %-9s %s"
              % (k, e.get("kind"), sec, e["seed"], x >> 16,
                 ca_ms if ca_ms is not None else "-",
                 " ".join("%d(%d)" % (p, u) for p, u in c)))
    if sets:
        common = set.intersection(*sets)
        plausible = {p for p in common if 1000 <= p < 0x8000}
        print("\nintersection over %d signings: %s" % (len(sets), sorted(common)))
        print("plausible (1000 <= pid16 < 0x8000): %s" % sorted(plausible))


if __name__ == "__main__":
    main()
