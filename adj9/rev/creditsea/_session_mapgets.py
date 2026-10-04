"""_session_mapgets.py — extract the mapget read order per signing from
adj9_cap_full.log, separate claims reads from JCA/Provider infrastructure."""
import re
import sys

LOG = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea\adj9_cap_full.log"

txt = open(LOG, encoding="utf-8", errors="replace").read()

recs = []
for chunk in txt.split("###ADJ9_BEGIN")[1:]:
    m = re.match(r"\s*type=(\w+) utf8len=\d+ ts=(\d+)", chunk)
    if not m:
        continue
    typ, ts = m.group(1), int(m.group(2))
    body = chunk
    rec = {"type": typ, "ts": ts}
    if typ == "mapget":
        tm = re.search(r"text: th=(\S+) this=(\d+) key=(.*?) val=(.*)", body)
        if tm:
            rec.update(th=tm.group(1), this=tm.group(2),
                       key=tm.group(3), val=tm.group(4))
        else:
            rec.update(th=None, this=None, key=None, val=None)
    elif typ == "sign_input":
        mo = re.search(r"map_order=([^\n]*)", body)
        mk = re.search(r"map_size=(\d+)", body)
        val, order = {}, []
        if mo:
            for part in mo.group(1).split("\x02"):
                if "\x01" in part:
                    k, v = part.split("\x01", 1)
                    val[k] = v
                    order.append(k)
        rec.update(val=val, order=order,
                   size=int(mk.group(1)) if mk else -1)
    elif typ in ("nsign", "nsign_native", "nsign_in", "nsign_signer_state"):
        rec["body"] = body[:200]
    recs.append(rec)

recs.sort(key=lambda r: r["ts"])

# signing anchor points
signs = [r for r in recs if r["type"] == "sign_input"]
natives = [r for r in recs if r["type"] == "nsign_native"]
print("sign_input records:", [(s["ts"], s.get("val", {}).get("activity_kind"),
                               s.get("size")) for s in signs])
print("nsign_native records:", [(n["ts"],) for n in natives])
print()

# For each nsign_native (native returned), collect mapgets in the window
# [native.ts - 1200ms, native.ts] (the nSign call window).
for n in natives:
    lo, hi = n["ts"] - 1200, n["ts"]
    win = [r for r in recs if r["type"] == "mapget" and lo <= r["ts"] <= hi]
    # group by map object id
    groups = {}
    for r in win:
        groups.setdefault(r["this"], []).append(r)
    print("=" * 78)
    print("nsign_native ts=%d  (window %d..%d, %d mapgets, %d distinct map objs)"
          % (n["ts"], lo, hi, len(win), len(groups)))
    for this, rows in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        keys = [r["key"] for r in rows]
        # split claims-like keys from JCA infrastructure
        jca = [k for k in keys if k and (k.startswith("java.") or k.startswith("sun.")
                                         or k.startswith("[") or "." in k)]
        claims = [k for k in keys if k not in jca]
        print("\n  map this=%s  ngets=%d" % (this, len(rows)))
        print("  CLAIM read order (%d): %s" % (len(claims), claims))
        if jca:
            u = []
            for k in jca:
                if k not in u:
                    u.append(k)
            print("  JCA/other (%d uniq): %s" % (len(u), u[:6]))
    print()
