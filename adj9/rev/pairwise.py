"""pairwise.py - decisive pairwise tests on the joined matrix:
  P1: als7 vs als9: SAME d10 claims (created .678, len 360) => same map, but
      DIFFERENT region (d2 fb1a8296 vs 4bce691e, d4 differ, d0 differ).
      Under law (B) region=f(map,second): seconds must differ. Under law (A)
      region=f(second): seconds must differ too. Either way: INVERT both
      blobs' seconds... but als has no stored blob! Use instead:
  P2: det0 vs det2: same payload (720B identical), same created_at (.678):
      regions differ. Same finding as P1 on independent harvests.
  P3: wh4[0] vs als4: same created (.112): wh4[0] sec=1789240075. als4's blob
      second unknown (no blob stored). BUT the nsign hex for wh4[0] IS stored;
      and als4's region came from whcap EMIT harvest of SOME signing - if that
      signing is wh4[0]'s, regions must match. Compare als4 region vs the
      region EMITs of nsign0 in whcap_hits7 (desc_det already pairs by ev?).
Report P1/P2 as the formal refutation of region=f(map), and set up P3.
"""
import os
import json

HERE = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
D = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))

print("=== P1: als7 vs als9 (same claims bytes?) ===")
print("d10 equal:", A[7]["d10"] == A[9]["d10"])
print("d0 equal:", A[7]["d0"] == A[9]["d0"])
print("d2:", A[7]["d2"], "vs", A[9]["d2"])
print("d4 equal:", A[7]["d4"] == A[9]["d4"])
print()
print("=== P2: det0 vs det2 (same payload?) ===")
print("payload equal:", D[0]["payload"] == D[2]["payload"])
print("d0 equal:", D[0]["d0"] == D[2]["d0"])
print("d2:", D[0]["d2"], "vs", D[2]["d2"])
print("d4 equal:", D[0]["d4"] == D[2]["d4"])
print()
print("CONCLUSION: region != f(map). The region varies across signings of the")
print("byte-identical map. Remaining candidates: f(second), f(map,second), or")
print("per-call fresh (heap/time-ns/pid). Slice 116's doublet (same map + same")
print("second -> identical body) kills per-call-fresh AND leaves f(second) vs")
print("f(map,second) open. A same-second DIFFERENT-map pair decides.")
print("done")
