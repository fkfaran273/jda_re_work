# oracle_analyze.py — extract every nSign call from oracle_run*.log with its
# experiment tag, then diff same-header (same-second) pairs to learn what feeds
# the 176-byte body: H (arg3)? the map? apiLevel?
import re, glob, struct, json, collections

def parse_events(path):
    ev, cur = [], None
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\S+) ts=(\d+)", ln)
        if m:
            cur = {"type": m.group(1), "ts": int(m.group(3)), "body": []}
            ev.append(cur); continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"): cur = None; continue
            cur["body"].append(ln.rstrip("\n"))
    return ev

def txt(e): return "\n".join(e["body"])

def fld(e, name):
    m = re.search(r"(?:^|\s)" + name + r"=([^\s]+)", txt(e), re.M)
    return m.group(1) if m else None

def hx(e, name):
    v = fld(e, name)
    return bytes.fromhex(v) if v else None

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from header_gen import make_header

calls = []   # {run, t_in, t_out, arg3, arg4, blob, inner:[events], tag}
for path in sorted(glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/oracle_run*.log")):
    run = os.path.basename(path)
    ev = parse_events(path)
    pend = None
    for idx, e in enumerate(ev):
        t = e["type"]
        if t == "nsign_in":
            pend = {"run": run, "t_in": e["ts"], "arg3": fld(e, "arg3_hex"),
                    "arg4": fld(e, "arg4_int"), "inner": []}
        elif t == "nsign" and pend is not None:
            h = fld(e, "hex")
            if not h:
                calls.append(dict(pend, t_out=e["ts"], blob=None, tag=None)); pend = None; continue
            pend["blob"] = bytes.fromhex(h); pend["t_out"] = e["ts"]
            # tag = nearest oracle_* marker event AFTER this nsign (<=60ms)
            tag = None
            for j in range(idx + 1, min(idx + 6, len(ev))):
                if ev[j]["type"].startswith("oracle_"):
                    if ev[j]["ts"] - e["ts"] <= 60: tag = ev[j]["type"]
                    break
            calls.append(dict(pend, tag=tag))
            pend = None
        elif pend is not None:
            pend["inner"].append(e)
    # remaining pend dropped

print("total nSign calls:", len(calls))
ok = [c for c in calls if c.get("blob")]
print("with 192B blob:", len(ok))
for c in ok:
    hdr = c["blob"][:16]
    seed_hit = None
    for lbl in ("t_in", "t_out"):
        for d in (0, 1):
            if make_header(c[lbl] // 1000 + d) == hdr:
                seed_hit = (lbl, d); break
        if seed_hit: break
    mac = [e for e in c["inner"] if e["type"] == "jca_mac_doFinal"]
    mac_out = fld(mac[-1], "hex") if mac else None
    mac_in_len = None
    mu = [e for e in c["inner"] if e["type"] == "jca_mac_update"]
    if mu: mac_in_len = fld(mu[-1], "len")
    print("%-16s t=%d dur=%4dms tag=%-18s arg3=%s.. lvl=%s  hdrOK=%s  mac(in=%s)->%s.." % (
        c["run"].replace("oracle_run", "").replace(".log", ""), c["t_in"], c["t_out"] - c["t_in"],
        str(c["tag"]), (c["arg3"] or "?")[:12], c["arg4"], seed_hit, mac_in_len, (mac_out or "?")[:12]))

# ---- same-header groups -> body diffs ----
print("\n=== same-header (same-second) groups ===")
byhdr = collections.defaultdict(list)
for c in ok:
    byhdr[c["blob"][:16]].append(c)
for hdr, cs in byhdr.items():
    if len(cs) < 2: continue
    print("\nheader %s  members=%d  tags=%s" % (hdr.hex(), len(cs), [c["tag"] or ("run%s@%d" % (c["run"][-5], c["t_out"])) for c in cs]))
    for a in range(len(cs)):
        for b in range(a + 1, len(cs)):
            A, B = cs[a], cs[b]
            ba, bb = A["blob"][16:], B["blob"][16:]
            diff = [i for i in range(176) if ba[i] != bb[i]]
            same = [i for i in range(176) if ba[i] == bb[i]]
            print("  %s(arg3=%s..) vs %s(arg3=%s..): body diff %d/176 bytes; same-pos: %s" % (
                A["tag"] or "ctl", (A["arg3"] or "?")[:8], B["tag"] or "ctl", (B["arg3"] or "?")[:8],
                len(diff), (same[:20] if same else "none")))
            if len(diff) <= 40:
                for i in diff:
                    print("      off=%3d  %02x -> %02x" % (i, ba[i], bb[i]))

# also dump the full bodies of the interesting tags for manual study
print("\n=== full bodies by tag (first occurrence each) ===")
seen = set()
for c in ok:
    tg = c["tag"] or "control"
    if tg in seen: continue
    seen.add(tg)
    print("\n[%s]  hdr=%s" % (tg, c["blob"][:16].hex()))
    print("  arg3=%s" % c["arg3"])
    print("  body=%s" % c["blob"][16:].hex())
