# desc_det.py - THE #0/#2/#8 determinism test (pure-Python-signer gate).
# Walk the whole EMIT stream sequentially: signing = field loop (36,5,4,8,1,1,
# L,1,1 dwords, distinct sinks, sequential pos) + merge run (same sink, 0x19
# handshake). Pair each signing to its nsign record via created_at from #10,
# recover second via the header law, then test: same second => same #0/#2/#8?
import json, os, re, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

DEV = os.path.join(os.path.dirname(HERE), "device")
d = json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
evs = [e for e in d if e.get("tag") == "emit"]
print("emit events:", len(evs))

def take(i, n, sink0):
    """consume n same-sink sequential-pos events starting at i"""
    sink = evs[i]["sink"]
    vals = []
    for j in range(n):
        e = evs[i + j]
        assert e["sink"] == sink, "sink change at +%d" % j
        assert int(e["pos"], 16) == j, "pos %d != %d" % (int(e["pos"], 16), j)
        vals.append(int(e["val"], 16))
    if sink0 is not None:
        assert sink != sink0, "field reuses previous sink"
    return vals, sink, i + n

signings = []
i, prev_sink = 0, None
while i < len(evs) - 60:
    try:
        f0, s0, i2 = take(i, 36, prev_sink)
        f9, s9, i3 = take(i2, 5, s0)
        if f9[0] != 0xFAD0F10D:
            i += 1; continue
        f8, s8, i4 = take(i3, 4, s9)
        f4, s4, i5 = take(i4, 8, s8)
        fa, sa, i6 = take(i5, 1, s4)
        fb, sb, i7 = take(i6, 1, sa)
        # #10: variable len 90 (session) or 97 (click); peek #10 head for 'KlcA'
        head = evs[i7]
        if int(head["val"], 16) != 0x4B6C6341:
            i += 1; continue
        sink10 = head["sink"]
        vals10, pos = [], 0
        j = i7
        while j < len(evs) and evs[j]["sink"] == sink10:
            p = int(evs[j]["pos"], 16)
            if p != pos:
                break
            vals10.append(int(evs[j]["val"], 16))
            pos += 1
            j += 1
        i8 = j
        f5, s5, i9 = take(i8, 1, sink10)
        f6, s6, iA = take(i9, 1, s5)
    except (AssertionError, IndexError):
        i += 1
        continue
    kind = "click" if len(vals10) == 97 else "session"
    b10 = b"".join(struct.pack(">I", v) for v in vals10)
    m = re.search(rb"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\+\d{4})", b10)
    ca = m.group(1).decode() if m else None
    m2 = re.search(rb"(click|session)$", b10)
    if m2:
        kind = m2.group(1).decode()
    signings.append({
        "kind": kind, "d0": f0, "d9": f9, "d8": f8, "d4": f4,
        "d2": fa[0], "d7": fb[0], "d10": vals10, "created_at": ca,
    })
    prev_sink = s6
    i = iA
    # skip the merge run (same-sink run starting with the 0x19 handshake)
    if i < len(evs) and evs[i]["sink"] != prev_sink:
        msink = evs[i]["sink"]
        while i < len(evs) and evs[i]["sink"] == msink:
            i += 1

print("signings segmented:", len(signings))
for k, s in enumerate(signings):
    print("  S%d %-7s ca=%s d2=%08x d7=%08x d8=%s" % (
        k, s["kind"], s["created_at"], s["d2"], s["d7"],
        b"".join(struct.pack(">I", x) for x in s["d8"]).hex()))

# ---- nsign records + seconds via header law + created_at from sign_inputs ----
log = open(os.path.join(DEV, "adj9_wh4.log"), "rb").read().decode(
    "utf-8", errors="replace")
recs = re.findall(
    r"###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n"
    r"text: len=\d+\nnano_out=\d+\nhex=([0-9a-f]+)", log)
recs = [(int(ts), bytes.fromhex(hx)) for ts, hx in recs]
print("\nnsign records:", len(recs))
for ri, (ts, blob) in enumerate(recs):
    sec = None
    for cand in range(ts // 1000 - 30, ts // 1000 + 3):
        if make_header(cand) == blob[:16]:
            sec = cand
            break
    recs[ri] = (ts, blob, sec)
    print("  R%d ts=%d sec=%s hdr=%s" % (ri, ts, sec, blob[:16].hex()))

# sign_input records: created_at comes from the desc10 value itself; match the
# timestamp to the nsign record whose second's header the blob carries.
def signing_sec(s):
    """created_at (from the signing's own #10) -> the nsign record whose
    header law second agrees with the timestamp's wall second."""
    if not s["created_at"]:
        return None
    import calendar, datetime
    dt = datetime.datetime.strptime(s["created_at"][:19], "%Y-%m-%dT%H:%M:%S")
    # created_at is local (+0200 here) while the header seconds are UTC epoch
    off = s["created_at"][-5:]
    sign = 1 if off[0] == "+" else -1
    wall = calendar.timegm(dt.timetuple()) - sign * (int(off[1:3]) * 3600 +
                                                     int(off[3:5]) * 60)
    best = None
    for ts, blob, sec in recs:
        if sec is None:
            continue
        if abs(sec - wall) <= 3:
            best = sec
    return best

print("\n--- pairing ---")
for k, s in enumerate(signings):
    s["sec"] = signing_sec(s)
    print("  S%d %s -> sec=%s" % (k, s["created_at"], s["sec"]))

print("\n--- DETERMINISM TEST: same second => same descriptors? ---")
groups = {}
for s in signings:
    if s["sec"] is not None:
        groups.setdefault(s["sec"], []).append(s)
found = False
for sec, ss in sorted(groups.items()):
    for a in range(len(ss)):
        for b in range(a + 1, len(ss)):
            found = True
            A, B = ss[a], ss[b]
            print("sec=%d %s vs %s: d0=%s d2=%s d4=%s d8=%s d7=%s d10=%s" % (
                sec, A["kind"], B["kind"],
                "EQ" if A["d0"] == B["d0"] else "DIFF",
                "EQ" if A["d2"] == B["d2"] else "DIFF",
                "EQ" if A["d4"] == B["d4"] else "DIFF",
                "EQ" if A["d8"] == B["d8"] else "DIFF",
                "EQ" if A["d7"] == B["d7"] else "DIFF",
                "EQ" if A["d10"] == B["d10"] else "DIFF"))
if not found:
    print("no same-second signing pair in this trace; seconds seen:",
          sorted({s["sec"] for s in signings if s["sec"] is not None}))
json.dump([{k: (v if k != "d10" else len(v)) for k, v in s.items()}
           for s in signings],
          open(os.path.join(HERE, "desc_det_result.json"), "w"), indent=1)
