#!/usr/bin/env python3
"""canon_rule.py — validate the canonical reconstruction rule against the
captured device canonical (corpus.json map_toString):
    canonical = query params (wire order) + client_sdk + adj_verification
                + headers_id + adj_signing_id + native_version + algorithm
Java LinkedHashMap.toString: {k=v, k=v} with nulls as literal 'null'."""
import json, sys
HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
DEV = r"C:\Users\Apps\Downloads\com.penti.app\adj9\device"
sys.stdout.reconfigure(line_buffering=True)

CONST = [("client_sdk", "android5.7.0"),
         ("adj_verification", "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"),
         ("headers_id", "10"),
         ("adj_signing_id", "1500000"),
         ("native_version", "5.0.0"),
         ("algorithm", "adj9")]

corpus = json.load(open(f"{HERE}\\corpus.json", encoding="utf-8"))
rows = corpus if isinstance(corpus, list) else corpus.get("rows") or corpus.get("sessions") or []
print("corpus rows:", len(rows))
ok = bad = 0
for r in rows:
    q = r.get("query_string") or r.get("query") or ""
    target = r.get("map_toString") or ""
    if not q or not target:
        continue
    from urllib.parse import unquote
    pairs = []
    for tok in q.split("&"):
        if "=" in tok:
            k, v = tok.split("=", 1)
            pairs.append((k, unquote(v)))
    pairs += [(k, v) for k, v in CONST if k not in dict(pairs)]
    built = "{" + ", ".join(f"{k}={v}" for k, v in pairs) + "}"
    if built == target:
        ok += 1
        print("  MATCH", dict(pairs).get("activity_kind"), len(built))
    else:
        bad += 1
        # show first divergence
        i = next((j for j, (a, b) in enumerate(zip(built, target)) if a != b), min(len(built), len(target)))
        print(f"  DIFF  {dict(pairs).get('activity_kind')} len {len(built)} vs {len(target)} @ {i}")
        print("   ours :", built[max(0,i-40):i+60])
        print("   dev  :", target[max(0,i-40):i+60])
print(f"OK {ok} / DIFF {bad}")
