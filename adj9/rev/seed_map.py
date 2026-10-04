# seed_map.py — for every 192B blob we own, brute-force WHICH unix second produces
# its 16-byte header under the verified header law.  Tells us (a) whether the law
# generalises past the 36/36 sample and (b) exactly WHEN inside the call srand()
# fires (offset from t0).
import re, glob, struct, sys
from header_gen import make_header

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

rows = {}
for e in parse_events("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/oracle_run7.log"):
    if not (e["type"].startswith("rapid_batch") or e["type"] == "rapid_fire"):
        continue
    T = "\n".join(e["body"])
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=(\d+) sec=(\d+) len=192\n([0-9a-f]+)", T):
        i = int(m.group(1))
        if len(m.group(6)) == 384:
            rows[i] = (int(m.group(2)), int(m.group(3)), bytes.fromhex(m.group(6)))

print("full 192B rapid rows:", len(rows))
cache = {}
def hdr(sec):
    if sec not in cache: cache[sec] = make_header(sec)
    return cache[sec]

print("\nrow  t0(ms)     dur   header              seed_sec      seed-t0   match")
ok = 0
for i in sorted(rows):
    t0, t1, b = rows[i]
    found = None
    for s in range(t0 // 1000 - 3, t1 // 1000 + 4):
        if hdr(s) == b[:16]:
            found = s; break
    if found: ok += 1
    print("%3d  %d  %4d  %s  %-14s  %s" % (
        i, t0, t1 - t0, b[:16].hex(),
        str(found), ("%+.3fs" % ((found - t0 / 1000.0))) if found else "-"))
print("\nheader law: %d/%d rapid rows matched a seed second in [t0-3s, t1+3s]" % (ok, len(rows)))
