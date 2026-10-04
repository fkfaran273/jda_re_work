"""parse_mapget_windows.py -- extract the nSign mapget query sequence per signing.

Between a `nsign_in` event and its matching `nsign` event the native signer
queries the request map key by key (hook type=mapget, text `this=.. key=K val=V`).
The query order IS the claims emission order.  The following `sign_input` event
carries map_toString, which identifies activity_kind.

Output: one line per signing: ts, kind, mapget-key sequence (claims-shaped keys
only: snake_case identifiers), plus val for each query.
"""
import re
import sys

pat_begin = re.compile(r"###ADJ9_BEGIN type=([a-z_0-9]+) utf8len=(\d+) ts=(\d+)")
pat_key = re.compile(r" key=(\S+) val=(.*)$")
pat_kind = re.compile(r"activity_kind=([a-z_]+)")
CLAIM_KEY = re.compile(r"^[a-z_][a-z_0-9]*$")


def parse(path):
    cur_type = None
    cur_ts = 0
    buf = []
    out = []          # (ts, type, payload) in log order
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pat_begin.match(line)
            if m:
                cur_type, cur_ts = m.group(1), int(m.group(3))
                buf = []
                continue
            if line.startswith("###ADJ9_END"):
                out.append((cur_ts, cur_type, "\n".join(buf)))
                cur_type = None
                buf = []
                continue
            if cur_type:
                buf.append(line.rstrip("\n"))

    signings = []
    window = None
    for ts, typ, body in out:
        if typ == "nsign_in":
            window = {"t0": ts, "gets": []}
        elif typ == "mapget" and window is not None:
            for ln in body.splitlines():
                if ln.startswith("text: "):
                    km = pat_key.search(ln)
                    if km:
                        window["gets"].append((km.group(1), km.group(2)))
        elif typ == "nsign" and window is not None:
            window["t1"] = ts
            signings.append(window)
            window = None
        elif typ == "sign_input":
            pend = body
            signings.append({"sign_input": ts, "body": pend})
    # pair each nsign window with the NEXT sign_input (they come in pairs:
    # nsign_in..nsign then sign_input with the same map)
    return signings


def main(path):
    evs = parse(path)
    # rebuild: keep order, join nsign windows with the nearest following sign_input
    rows = []
    last_win = None
    for e in evs:
        if "gets" in e:
            last_win = e
        else:
            body = e.get("body", "")
            km = pat_kind.search(body)
            kind = km.group(1) if km else "?"
            rows.append((e["sign_input"], kind, last_win))
            last_win = None
    for ts, kind, win in rows:
        gets = win["gets"] if win else []
        keys = [k for k, v in gets if CLAIM_KEY.match(k)]
        print("ts=%d kind=%s nsign_gets=%d" % (ts, kind, len(gets)))
        print("   keys: " + " | ".join("%s=%s" % (k, v) for k, v in gets
                                        if CLAIM_KEY.match(k)))
        print()


if __name__ == "__main__":
    main(sys.argv[1])
