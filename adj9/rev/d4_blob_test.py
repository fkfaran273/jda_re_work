# d4_blob_test.py - is trace #4 (H) a substring of the corresponding nsign blob?
# And: do the two same-second session signings (S0, S2) map to two DIFFERENT
# nsign records with DIFFERENT maps? -> settles whether H is randomized or the
# message differs.
import json, os, re, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.path.insert(0, HERE)
from header_gen import make_header

d = json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
evs = [e for e in d if e.get("tag") == "emit"]

def take(i, n):
    sink = evs[i]["sink"]
    vals = []
    for j in range(n):
        e = evs[i + j]
        assert e["sink"] == sink and int(e["pos"], 16) == j
        vals.append(int(e["val"], 16))
    return vals, sink, i + n

signings = []
i, prev = 0, None
while i < len(evs) - 60:
    try:
        f0, s0, i2 = take(i, 36)
        if s0 == prev:
            i += 1; continue
        f9, s9, i3 = take(i2, 5)
        if f9[0] != 0xFAD0F10D:
            i += 1; continue
        f8, s8, i4 = take(i3, 4)
        f4, s4, i5 = take(i4, 8)
        fa, sa, i6 = take(i5, 1)
        fb, sb, i7 = take(i6, 1)
        if int(evs[i7]["val"], 16) != 0x4B6C6341:
            i += 1; continue
        s10 = evs[i7]["sink"]
        v10, pos, j = [], 0, i7
        while j < len(evs) and evs[j]["sink"] == s10 and int(evs[j]["pos"], 16) == pos:
            v10.append(int(evs[j]["val"], 16)); pos += 1; j += 1
        f5, s5, i9 = take(j, 1)
        f6, s6, iA = take(i9, 1)
    except (AssertionError, IndexError):
        i += 1; continue
    b10 = b"".join(struct.pack(">I", v) for v in v10)
    m = re.search(rb"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\+\d{4})", b10)
    k = re.search(rb"(click|session)$", b10)
    signings.append({
        "kind": k.group(1).decode() if k else "?",
        "ca": m.group(1).decode() if m else None,
        "d0": b"".join(struct.pack(">I", v) for v in f0),
        "d2": struct.pack(">I", fa[0]),
        "d4": b"".join(struct.pack(">I", v) for v in f4),
        "d8": b"".join(struct.pack(">I", v) for v in f8),
        "d10": b10,
    })
    prev = s6
    i = iA
    if i < len(evs) and evs[i]["sink"] != prev:
        ms = evs[i]["sink"]
        while i < len(evs) and evs[i]["sink"] == ms:
            i += 1

print("signings:", len(signings))
for n, s in enumerate(signings):
    s["sec"] = None
    print("  S%d %-7s ca=%s" % (n, s["kind"], s["ca"]))

log = open(os.path.join(DEV, "adj9_wh4.log"), "rb").read().decode(
    "utf-8", errors="replace")
recs = [(int(ts), bytes.fromhex(hx)) for ts, hx in re.findall(
    r"###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n"
    r"text: len=\d+\nnano_out=\d+\nhex=([0-9a-f]+)", log)]
print("\nnsign records:", len(recs))
for ri, (ts, b) in enumerate(recs):
    sec = None
    for c in range(ts // 1000 - 30, ts // 1000 + 3):
        if make_header(c) == b[:16]:
            sec = c; break
    hits = []
    for n, s in enumerate(signings):
        where = []
        if s["d4"] in b:
            where.append("d4@%d" % b.index(s["d4"]))
        if s["d0"] in b:
            where.append("d0@%d" % b.index(s["d0"]))
        if s["d2"] in b:
            where.append("d2@%d" % b.index(s["d2"]))
        if s["d8"] in b:
            where.append("d8@%d" % b.index(s["d8"]))
        if s["d10"] in b:
            where.append("d10@%d" % b.index(s["d10"]))
        if where:
            hits.append("S%d[%s]" % (n, ",".join(where)))
    print("  R%d ts=%d sec=%s %s : %s" % (ri, ts, sec, b[:4].hex(),
                                          " ".join(hits) or "-"))

# which nsign blob carries each signing's desc10 (the map identity)?
print("\n--- map identity (desc10 in blob) ---")
for n, s in enumerate(signings):
    for ri, (ts, b) in enumerate(recs):
        if s["d10"] in b:
            print("  S%d %s desc10(len %d) -> R%d blob %s" % (
                n, s["kind"], len(s["d10"]), ri, b[:4].hex()))
            s["rec"] = ri
# do S0 and S2 have identical desc10 (same map)?
same = [n for n in range(len(signings)) if signings[n]["d10"] == signings[0]["d10"]]
print("\ndesc10 identical to S0:", same)
print("S0 d4:", signings[0]["d4"].hex())
print("S2 d4:", signings[2]["d4"].hex())