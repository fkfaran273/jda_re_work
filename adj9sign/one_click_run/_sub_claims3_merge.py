"""_sub_claims3_merge.py — merge all claims3 stage outputs into the single
deliverable _sub_claims3_out.json (stages + totals + hit list + notes).
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = {
    "rerun_R1_R5": "_sub_claims3_out.json",
    "stage6r": "_sub_claims3_stage6r_out.json",
    "stage7b": "_sub_claims3_stage7b_out.json",
    "stage8": "_sub_claims3_stage8_out.json",
    "stage9": "_sub_claims3_stage9_out.json",
    "stage10": "_sub_claims3_stage10_out.json",
    "strcrack": "_sub_claims3_strcrack_out.json",
}

merged = {"stages": {}, "hits": [], "sources": {}}
for src, fn in FILES.items():
    p = os.path.join(HERE, fn)
    if not os.path.exists(p):
        continue
    with open(p) as f:
        d = json.load(f)
    if src == "strcrack":
        merged["sources"][src] = {"file": fn, "n_strings": len(d)}
        continue
    stages = d.get("stages", {})
    for name, s in stages.items():
        key = name if src == "rerun_R1_R5" else "%s__%s" % (src, name)
        s2 = dict(s)
        s2["source"] = src
        merged["stages"][key] = s2
    merged["hits"].extend(d.get("hits", []))
    merged["sources"][src] = {"file": fn, "stages": list(stages)}

total = sum(s.get("n", 0) for s in merged["stages"].values())
merged["totals"] = {
    "n_candidates_corrected": total,
    "n_hits": len(merged["hits"]),
}
with open(os.path.join(HERE, "_sub_claims3_out.json"), "w") as f:
    json.dump(merged, f, indent=1)
print("merged stages:", len(merged["stages"]))
print("total candidates (corrected runs):", total)
print("total hits:", len(merged["hits"]))
