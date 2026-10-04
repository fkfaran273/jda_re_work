"""replay_device.py — THE decisive cross-check.

Replay the REAL device's nSign calls (captured by the LSPosed oracle) through
our Unicorn mint: same map, same H (arg2), same int (arg3=31 = API level),
same second.  If our blob == the device blob, the algorithm is fully decoded
and the Organic problem is NOT the signature.  If it differs, we are missing
part of the algorithm (most likely the key2 path).
"""
import calendar
import datetime
import re
import sys

sys.path.insert(0, "..")
import adj8_pure as S

LOG = "device_capture_adj8.log"
lines = [l.split(" D ADJ9ORA : ", 1)[1].rstrip("\n")
         for l in open(LOG, encoding="utf-8", errors="replace")
         if " D ADJ9ORA : " in l]

# ---- group signer_sign_entry chunks chronologically ------------------------
groups = []
cur = None
for l in lines:
    m = re.match(r"signer_sign_entry#(\d+) :: (.*)$", l)
    if m:
        n = int(m.group(1))
        if n == 0:
            if cur is not None:
                groups.append(cur)
            cur = m.group(2)
        elif cur is not None:
            cur += m.group(2)
if cur is not None:
    groups.append(cur)
print("signing groups:", len(groups))


def parse_map(text):
    inner = text.strip()
    if inner.startswith("{"):
        inner = inner[1:]
    if inner.endswith("}"):
        inner = inner[:-1]
    out = {}
    for pair in inner.split(", "):
        if "=" in pair:
            a, b = pair.split("=", 1)
            out[a] = b
    return out


def created_epoch(created):
    # format: 2026-10-03T00:59:15.833Z+0530  (local wall clock + offset)
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z([+-]\d{4})",
                 created)
    dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f")
    off = m.group(2)
    minutes = (1 if off[0] == "+" else -1) * (int(off[1:3]) * 60 + int(off[3:5]))
    return calendar.timegm(dt.timetuple()) - minutes * 60


signings = []
for g in groups:
    kind = re.search(r"activity_kind=([a-z_]+)", g)
    kind = kind.group(1) if kind else "?"
    maps = re.findall(r"map\{\|(.*?)\|\}", g, re.S)
    arg1 = parse_map(maps[0]) if maps else {}
    arg2 = parse_map(maps[1]) if len(maps) > 1 else {}
    merged = dict(arg1)
    merged.update(arg2)
    merged.pop("endpoint", None)          # not a claim-pool key
    created = merged.get("created_at", "")
    sec = created_epoch(created) if created else None
    signings.append({"kind": kind, "map": merged, "created": created,
                     "sec": sec, "n": len(merged)})
    print("%-11s fields=%-3d created=%s (sec %s)"
          % (kind, len(merged), created, sec))

# ---- H values (chronological mac_doFinal, deduped) -------------------------
H = []
for l in lines:
    m = re.match(r"jca_mac_doFinal#\d+ :: out=32\|hex=([0-9a-f]{64})", l)
    if m and m.group(1) not in H:
        H.append(m.group(1))
print("H values (chronological):", [h[:12] for h in H])

# ---- device blobs (nsign_native) -------------------------------------------
blobs = []
for l in lines:
    m = re.match(r"nsign_native#\d+ :: (.*)$", l)
    if m:
        for bm in re.finditer(r"out_len=176\|out_hex=([0-9a-f]{352})", m.group(1)):
            b = bytes.fromhex(bm.group(1))
            if b not in blobs:
                blobs.append(b)
print("device blobs:", len(blobs))

for b in blobs:
    seed = next((c for c in range(1790969300, 1790969500)
                 if S.make_header(c) == b[:16]), None)
    print("blob hdr:", b[:16].hex(), "seed:", seed)

# ---- pair blobs to signings by header seed, then replay --------------------
print()
results = []
for b in blobs:
    seed = next((c for c in range(1790969300, 1790969500)
                 if S.make_header(c) == b[:16]), None)
    if seed is None:
        print("blob %s... : no seed" % b[:8].hex())
        continue
    match = [s for s in signings if s["sec"] and abs(s["sec"] - seed) <= 3]
    if not match:
        print("blob %s... : no signing group at sec %d" % (b[:8].hex(), seed))
        continue
    s = match[0]
    hi = signings.index(s)
    if hi >= len(H):
        print("no H for signing #%d" % hi)
        continue
    h = bytes.fromhex(H[hi])
    print("=== replay %s (sec=%d, H=%s..., map %d fields) ==="
          % (s["kind"], seed, H[hi][:12], s["n"]))
    emu = S.Emu()
    emu.fixed_time = seed
    out = emu.run(payload=h, mapobj=s["map"], arg4=31)
    if out is None:
        print("  mint FAILED")
        results.append((s["kind"], None, None))
        continue
    same = out == b
    diff = next((i for i in range(176) if out[i] != b[i]), None)
    print("  identical=%s  first diff=%d" % (same, diff))
    print("  mine[16:48] %s" % out[16:48].hex())
    print("  dev [16:48] %s" % b[16:48].hex())
    open("replay_%s.hex" % s["kind"], "w").write(out.hex())
    results.append((s["kind"], same, diff))

print("\nVERDICT:", results)
