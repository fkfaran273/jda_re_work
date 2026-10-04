# oracle_map.py — structure of oracle_run*.log: event types, nSign windows,
# and where the "1:...:android:..." b64 + SHA-1 chain sits relative to nSign.
import re, glob, collections, json

def parse_events(path):
    ev = []
    cur = None
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\S+) ts=(\d+)", ln)
        if m:
            cur = {"type": m.group(1), "ts": int(m.group(3)), "body": []}
            ev.append(cur); continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"): cur = None; continue
            cur["body"].append(ln.rstrip("\n"))
    return ev

def txt(e):
    return "\n".join(e["body"])

def hexfield(e, name="hex"):
    m = re.search(r"^" + name + r"=([0-9a-fA-F]*)$", txt(e), re.M)
    return m.group(1) if m else None

for path in sorted(glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/oracle_run*.log")):
    ev = parse_events(path)
    cnt = collections.Counter(e["type"] for e in ev)
    print("=" * 78)
    print(path.split("\\")[-1], " events:", len(ev))
    for k, v in cnt.most_common():
        print("   %-28s %d" % (k, v))
    # nSign windows: events between nsign_in and nsign
    wins = []
    cur = None
    for i, e in enumerate(ev):
        if e["type"] == "nsign_in":
            cur = {"i0": i, "t0": e["ts"], "inner": []}
        elif e["type"] == "nsign" and cur is not None:
            cur["t1"] = e["ts"]
            wins.append(cur); cur = None
        elif cur is not None:
            cur["inner"].append(e)
    print("  nSign windows:", len(wins))
    for w in wins[:6]:
        seq = [e["type"] for e in w["inner"]]
        # compress consecutive dupes
        comp = []
        for t in seq:
            if not comp or comp[-1][0] != t: comp.append([t, 1])
            else: comp[-1][1] += 1
        print("    win t=%d dur=%dms  %s" % (w["t0"], w.get("t1", 0) - w["t0"],
              " ".join("%s%s" % (t, ("x%d" % n) if n > 1 else "") for t, n in comp)))
    # where do b64 'flags=11' / SHA-1 md events sit vs windows?
    inside = lambda ts: any(w["t0"] <= ts <= w.get("t1", ts) for w in wins)
    b64_1 = [e for e in ev if e["type"] == "jca_b64_encodeToString" and "flags=11" in txt(e)]
    print("  b64 flags=11 events:", len(b64_1), " inside nSign:", sum(1 for e in b64_1 if inside(e["ts"])))
    for e in b64_1[:3]:
        m = re.search(r"hex_in=([0-9a-f]+)", txt(e))
        if m:
            raw = bytes.fromhex(m.group(1))
            print("     t=%d %s  in-window=%s" % (e["ts"], raw[:60].decode("utf-8", "replace"), inside(e["ts"])))
    md = [e for e in ev if e["type"] == "jca_md_digest"]
    print("  md_digest events:", len(md), " inside nSign:", sum(1 for e in md if inside(e["ts"])))
