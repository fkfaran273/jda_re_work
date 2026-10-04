# same_second.py - THE decisive test, on the freshest device mints.
#
# device/mint_out1.json + mint_out2.json are written by the agent's two back-to-back
# piggyback mints of the SAME map inside one Signer.sign() hook (main.js E1/E2).
# Under the proven header law (header == Random3(second)) each blob's own header
# reveals the second it was signed in, so same-second pairs can be compared.
#
#   same map + same second -> identical body  => deterministic => offline signer OK
#   same map + same second -> different body  => per-call randomness => impossible
import base64
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header            # noqa: E402

DEVF = "/sdcard/Android/data/com.penti.app/files"


def pull(name, dest):
    subprocess.run(["adb", "pull", "%s/%s" % (DEVF, name), dest],
                   capture_output=True)


def load(path):
    if not os.path.exists(path):
        return None
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return None


def sec_of(blob, span=7200):
    """recover the signing second from the blob header (proven law). The mints are
    fresh, so a tight window is enough and keeps the search cheap."""
    now = int(__import__("time").time())
    for s in range(now - span, now + 120):
        if make_header(s) == blob[:16]:
            return s
    return None


def main():
    a1 = os.path.join(HERE, "dev_n1.json")
    a2 = os.path.join(HERE, "dev_n2.json")
    pull("mint_out1.json", a1)
    pull("mint_out2.json", a2)
    A, B = load(a1), load(a2)
    if not (A and B):
        print("missing mint files")
        return
    rows = []
    for tag, d in (("mint1", A), ("mint2", B)):
        b = base64.b64decode(d["blobB64"])
        sec = sec_of(b)
        mp = {k: v for k, v in (d.get("mapPairs") or [])}
        rows.append({"tag": tag, "sec": sec, "blob": b, "map": mp,
                     "stamp": d.get("stamp"), "ok": d.get("ok")})
        print("%s ok=%s blob=%dB stamp=%s header=%s -> second=%s"
              % (tag, d.get("ok"), len(b), d.get("stamp"), b[:16].hex(), sec))
    ra, rb = rows
    print("\nmap identical : %s (%d vs %d keys)"
          % (ra["map"] == rb["map"], len(ra["map"]), len(rb["map"])))
    if ra["map"] != rb["map"]:
        for k in set(ra["map"]) | set(rb["map"]):
            if ra["map"].get(k) != rb["map"].get(k):
                print("   map DIFF %-24s %r vs %r"
                      % (k, ra["map"].get(k), rb["map"].get(k)))
    print("second identical: %s (%s vs %s)"
          % (ra["sec"] == rb["sec"], ra["sec"], rb["sec"]))
    same_body = ra["blob"][16:] == rb["blob"][16:]
    print("body identical  : %s" % same_body)
    d = [i for i in range(192) if ra["blob"][i] != rb["blob"][i]]
    print("bytes differing : %d/192" % len(d))
    if ra["sec"] == rb["sec"] and ra["map"] == rb["map"]:
        print("\n=== VERDICT: same map + same second -> body identical=%s ==="
              % same_body)
        print("    deterministic => an offline signer is possible" if same_body else
              "    NOT deterministic => the per-call region is random at signing")
    else:
        print("\n=== NOT a same-second pair: the control is still open ===")
    json.dump([{**{k: v for k, v in r.items() if k != 'blob'},
                "blob_hex": r["blob"].hex()} for r in rows],
              open(os.path.join(HERE, "same_second.json"), "w"), indent=1)


if __name__ == "__main__":
    main()