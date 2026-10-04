#!/usr/bin/env python3
"""wire_models.py — two decisive measurements:
A) header == Random3(sec) within +/-1s tolerance across 396 rapid blobs
B) from the raw wire dump: distinct Authorization signatures per endpoint kind
   (does the app reuse one stored blob for its polls, or sign fresh per call?)"""
import json, os, re, sys, collections, importlib.util
sys.stdout.reconfigure(line_buffering=True)
ADJ = r"C:\Users\Apps\Downloads\com.penti.app\adj9"

# ---------- A: tolerance ----------
d = json.load(open(os.path.join(ADJ, "rev", "corpus.json")))
spec = importlib.util.spec_from_file_location("afc", os.path.join(ADJ, "rev", "adj9_full_chain.py"))
afc = importlib.util.module_from_spec(spec); spec.loader.exec_module(afc)
items = [(r["sec"], bytes.fromhex(r["hex"])[:16]) for r in d["rapid"] if r.get("sec")]
ok1 = ok0 = bad = 0
for sec, hdr in items:
    preds = set()
    for ds in (-1, 0, 1):
        try:
            p = afc.make_header(sec + ds)
            preds.add(bytes(p if isinstance(p, (bytes, bytearray)) else bytes.fromhex(p)))
        except Exception:
            pass
    if hdr in preds:
        if hdr == preds.pop() if len(preds) == 1 else True:
            pass
        ok1 += 1
    else:
        bad += 1
print(f"A) header in Random3({{sec-1,sec,sec+1}}): {ok1}/{len(items)}  (outside: {bad})")

# ---------- B: wire dump signatures ----------
def harvest(path):
    try:
        raw = open(path, "rb").read().decode("latin1")
    except OSError:
        return []
    out = []
    for m in re.finditer(r"GET (/[a-z_0-9]+)\?[^\r\n ]+|POST (/[a-z_0-9]+)", raw):
        ep = m.group(1) or m.group(2)
        start = raw.find("Authorization: ", m.start())
        if start == -1 or start - m.start() > 4000:
            continue
        end = raw.find("\r\n", start)
        auth = raw[start + len("Authorization: "):end]
        sig = re.search(r'signature="([A-Za-z0-9+/=]+)"', auth)
        if sig:
            out.append((ep, sig.group(1)[:40]))
    return out

dumps = [r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin"]
rows = []
for p in dumps:
    rows += harvest(p)
by = collections.defaultdict(list)
for ep, sig in rows:
    by[ep].append(sig)
print("B) wire-dump Authorization signatures per endpoint:")
for ep, sigs in sorted(by.items()):
    uniq = len(set(sigs))
    print(f"  {ep:14s} n={len(sigs):2d} distinct_signatures={uniq}")
    for s in sigs[:4]:
        print(f"      {s}…")
