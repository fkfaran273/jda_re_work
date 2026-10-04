#!/usr/bin/env python3
"""Parse the full capture log into a structured corpus of
(record, H, blob) triples plus the oracle rapid-fire batches."""
import re, json, sys, os

LOG = os.path.join(os.path.dirname(__file__), "..", "device", "adj9_capture_full.log")
LOG = os.path.abspath(LOG)

def parse(path):
    recs = []
    cur = None
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)", line)
        if m:
            cur = {"type": m.group(1), "ts": int(m.group(3)), "body": []}
            continue
        if line.startswith("###ADJ9_END"):
            if cur is not None:
                recs.append(cur)
            cur = None
            continue
        if cur is not None:
            cur["body"].append(line.rstrip("\n"))
    for r in recs:
        r["text"] = "\n".join(r["body"])
        del r["body"]
    return recs

def field(txt, key):
    m = re.search(re.escape(key) + r"=([^\n]*)", txt)
    return m.group(1) if m else None

def main():
    recs = parse(LOG)
    print(f"records: {len(recs)}")
    from collections import Counter
    print(Counter(r["type"] for r in recs).most_common(12))

    # --- sign_input -> record
    sign_inputs = []
    for r in recs:
        if r["type"] != "sign_input":
            continue
        si = {
            "ts": r["ts"],
            "map_toString": field(r["text"], "map_toString"),
            "map_order": field(r["text"], "map_order"),
            "map_size": field(r["text"], "map_size"),
        }
        sign_inputs.append(si)
    print(f"sign_input: {len(sign_inputs)}")

    # --- nsign blobs
    blobs = []
    for r in recs:
        if r["type"] == "nsign":
            h = field(r["text"], "hex")
            if h:
                blobs.append({"ts": r["ts"], "blob": bytes.fromhex(h)})
    print(f"nsign blobs: {len(blobs)}")

    # --- nsign_in (H)
    hs = []
    for r in recs:
        if r["type"] == "nsign_in":
            hs.append({"ts": r["ts"], "H": field(r["text"], "arg3_hex"),
                       "lvl": field(r["text"], "arg4_int")})
    print(f"nsign_in: {len(hs)}")

    # --- rapid_fire / rapid_batch
    rapid = []
    for r in recs:
        if r["type"].startswith("rapid"):
            rows = re.findall(r"--- (\d+) t0=(\d+) t1=(\d+) ms=(\d+) sec=(\d+) len=(-?\d+)\n([0-9a-f]+)",
                              r["text"])
            for i, t0, t1, ms, sec, ln, hx in rows:
                rapid.append({"batch": r["type"], "i": int(i), "t0": int(t0),
                              "t1": int(t1), "sec": int(sec),
                              "blob": bytes.fromhex(hx) if int(ln) > 0 else None})
    print(f"rapid rows: {len(rapid)}")

    out = {"sign_inputs": sign_inputs, "blobs": blobs, "hs": hs, "rapid": rapid}
    dst = os.path.join(os.path.dirname(__file__), "corpus.json")
    # blob -> hex for json
    j = {
        "sign_inputs": sign_inputs,
        "blobs": [{"ts": b["ts"], "hex": b["blob"].hex()} for b in blobs],
        "hs": hs,
        "rapid": [{"batch": r["batch"], "i": r["i"], "t0": r["t0"], "sec": r["sec"],
                   "hex": r["blob"].hex() if r["blob"] else None} for r in rapid],
    }
    json.dump(j, open(dst, "w"), indent=1)
    print("wrote", dst)

if __name__ == "__main__":
    main()
