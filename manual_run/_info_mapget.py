"""_info_mapget.py -- extract the mapget key-query sequence from the creditsea
captures: during nSign the native signer queries the map key by key; the order
of the queries IS the claims key order (restricted to keys the map carries).
"""
import re, sys, glob

pat_begin = re.compile(r"###ADJ9_BEGIN type=([a-z_0-9]+) utf8len=(\d+) ts=(\d+)")
pat_text = re.compile(r"^text: (.*)$", re.M)

def entries(path):
    cur = None
    buf = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pat_begin.match(line)
            if m:
                if cur:
                    yield cur, "\n".join(buf)
                cur = (m.group(1), int(m.group(3)))
                buf = []
            elif cur is not None:
                if line.startswith("###ADJ9_END"):
                    yield cur, "\n".join(buf)
                    cur = None
                    buf = []
                else:
                    buf.append(line.rstrip("\n"))
        if cur:
            yield cur, "\n".join(buf)

def parse(path):
    evs = []
    for (typ, ts), body in entries(path):
        m = pat_text.search(body)
        text = m.group(1) if m else body.split("\nhex:")[0]
        if typ == "mapget":
            km = re.search(r" key=(.*) val=", text)
            key = km.group(1) if km else None
            evs.append((ts, "mapget", key))
        elif typ in ("sign_input", "authorization_header", "nsign_in", "nsign"):
            evs.append((ts, typ, text[:120].replace("\n", " | ")))
    return evs

for path in sys.argv[1:]:
    print("=====", path)
    evs = parse(path)
    # group mapget runs separated by >2s gaps
    runs, cur = [], []
    last = None
    for ts, typ, val in evs:
        if typ == "mapget":
            if last is not None and ts - last > 2000 and cur:
                runs.append(cur)
                cur = []
            cur.append((ts, val))
            last = ts
        else:
            if cur:
                runs.append(cur)
                cur = []
            print("  [%d] %s: %s" % (ts, typ, val[:110]))
    if cur:
        runs.append(cur)
    for r in runs:
        print("  ---- mapget run: %d keys, ts %d..%d" % (len(r), r[0][0], r[-1][0]))
        keys = [v for _, v in r]
        print("      " + " | ".join(keys))
