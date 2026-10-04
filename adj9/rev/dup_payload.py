# dup_payload.py - THE decisive test for the user's claim: is the blob a function of
# the payload, or does it carry per-call process state?
#
# Slice 112's evidence ("two signings of the byte-identical payload -> different
# #0/#2/#4") came from OUR segmentation of the Frida EMIT trace, which could be an
# artifact (a mis-paired or double-emitted signing). The device's own log settles
# it without any segmentation: adj9_wh.log holds 191 `nsign` blobs and 191
# `sign_input` records (the map_toString payload) with timestamps, so equal
# payloads can be paired to their blobs directly.
#
#   same payload -> same blob (or same body)  => deterministic => computable
#   same payload -> different body            => live per-call state
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
OUT = os.path.join(HERE, "dup_payload.json")


def parse(path):
    raw = open(path, "rb").read().decode("utf-8", errors="replace")
    bl = re.findall(r"###ADJ9_BEGIN type=(\w+)[^\n]*ts=(\d+)\n(.*?)###ADJ9_END",
                    raw, re.S)
    ns, si, mac = [], [], []
    for t, ts, body in bl:
        if t == "nsign":
            m = re.search(r"hex=([0-9a-f]{384})", body)
            if m:
                ns.append((int(ts), bytes.fromhex(m.group(1))))
        elif t == "sign_input":
            m = re.search(r"map_toString=\{(.*?)\}", body, re.S)
            if m:
                si.append((int(ts), m.group(1)))
        elif t == "nsign_in":
            m = re.search(r"arg3_hex=([0-9a-f]{64})", body)
            if m:
                mac.append((int(ts), m.group(1)))
    return ns, si, mac


def pair(signings, payloads, window=5000):
    """attach to each signing the payload logged within `window` ms after it"""
    out = []
    si = sorted(payloads)
    for ts, blob in signings:
        best = None
        for pts, p in si:
            d = pts - ts
            if 0 <= d <= window and (best is None or d < best[0]):
                best = (d, p)
        out.append({"ts": ts, "blob": blob, "payload": best[1] if best else None,
                    "lag_ms": best[0] if best else None})
    return out


def dw(b):
    return [b[i * 4:i * 4 + 4].hex() for i in range(48)]


def main():
    for fname in ("adj9_wh.log", "adj9_wh2.log"):
        p = os.path.join(DEV, fname)
        if not os.path.exists(p):
            continue
        ns, si, mac = parse(p)
        print("=== %s ===  nsign=%d sign_input=%d nsign_in=%d"
              % (fname, len(ns), len(si), len(mac)))
        rows = pair(ns, si)
        ok = [r for r in rows if r["payload"]]
        print("  paired signings: %d/%d" % (len(ok), len(rows)))
        g = defaultdict(list)
        for r in ok:
            g[r["payload"]].append(r)
        dup = {k: v for k, v in g.items() if len(v) > 1}
        print("  distinct payloads: %d   payloads signed more than once: %d"
              % (len(g), len(dup)))
        for payload, rs in list(dup.items())[:6]:
            print("\n  --- payload len=%d md='%s'  n=%d"
                  % (len(payload), payload[:60].replace("\n", " "), len(rs)))
            for r in rs:
                print("      ts=%d  hdr=%s  body0=%s"
                      % (r["ts"], r["blob"][:16].hex(), r["blob"][16:40].hex()))
            first = rs[0]["blob"]
            for r in rs[1:]:
                b = r["blob"]
                hdr = first[:16] == b[:16]
                body = first[16:] == b[16:]
                nd = sum(1 for i in range(16, 192, 4)
                         if first[i:i + 4] != b[i:i + 4])
                print("      vs first: header EQ=%s  body EQ=%s  body dwords differ=%d/44"
                      % (hdr, body, nd))
        same = sum(1 for payload, rs in dup.items()
                   if len({r["blob"][16:] for r in rs}) == 1)
        print("\n  duplicate payloads whose BODY is identical: %d/%d"
              % (same, len(dup)))
        json.dump([{**{k: (v.hex() if isinstance(v, bytes) else v)
                       for k, v in r.items()}} for r in ok],
                  open(OUT, "w"), indent=1)
        print("  saved %s" % OUT)
        return


if __name__ == "__main__":
    main()