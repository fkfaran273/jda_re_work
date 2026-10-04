# pull_mints.py - pull every mint_outN.json the agent wrote and look for same-header
# (i.e. same-second) pairs, then compare their bodies.
#
# Under the proven header law the first 16 bytes are Random3(signing_second), so two
# blobs sharing a header were produced in the SAME second:
#     identical body => the pipeline is deterministic given (map, H, second)
#     different body => per-call randomness in the #0/#2/#4 region
import base64
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header            # noqa: E402

DEVF = "/sdcard/Android/data/com.penti.app/files"
OUT = os.path.join(HERE, "pull_mints.json")


def sh(*a):
    r = subprocess.run(["adb"] + list(a), capture_output=True)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def main():
    listing = sh("shell", "ls", DEVF)
    names = sorted(n for n in listing.split() if n.startswith("mint_out")
                   and n.endswith(".json"))
    print("mint files on device: %d  %s" % (len(names), names[:12]))
    rows = []
    now = int(__import__("time").time())
    for n in names:
        dest = os.path.join(HERE, "pm_" + n)
        sh("pull", "%s/%s" % (DEVF, n), dest)
        try:
            d = json.load(open(dest, encoding="utf-8"))
        except Exception:
            continue
        b64 = d.get("blobB64")
        if not b64:
            print("  %-18s no blob (%s)" % (n, d.get("error")))
            continue
        blob = base64.b64decode(b64)
        sec = None
        for s in range(now - 3600, now + 120):
            if make_header(s) == blob[:16]:
                sec = s
                break
        rows.append({"file": n, "sec": sec, "hdr": blob[:16].hex(),
                     "body": blob[16:].hex(), "stamp": d.get("stamp"),
                     "map": dict((k, v) for k, v in (d.get("mapPairs") or []))})
        print("  %-18s %dB header=%s second=%s stamp=%s"
              % (n, len(blob), blob[:16].hex()[:16], sec, d.get("stamp")))
    print("\n=== same-second pairs ===")
    hits = 0
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            a, b = rows[i], rows[j]
            if a["hdr"] != b["hdr"]:
                continue
            hits += 1
            print("  %s vs %s  same map=%s  body identical=%s"
                  % (a["file"], b["file"], a["map"] == b["map"],
                     a["body"] == b["body"]))
    print("  same-header pairs: %d" % hits)
    if hits:
        print("VERDICT: %s"
              % ("DETERMINISTIC given (map,H,second) -> extract the region offline"
                 if all(rows[i]["body"] == rows[j]["body"]
                        for i in range(len(rows)) for j in range(i + 1, len(rows))
                        if rows[i]["hdr"] == rows[j]["hdr"])
                 else "NON-DETERMINISTIC -> per-call randomness in the region"))
    else:
        print("VERDICT: no same-second pair captured yet")
    json.dump(rows, open(OUT, "w"), indent=1)
    print("saved %s" % OUT)


if __name__ == "__main__":
    main()