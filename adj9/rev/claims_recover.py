# claims_recover.py - re-run the desc_det.py segmentation on whcap_hits7.json
# but dump the FULL d10 claim bytes for S0/S1/S2 (desc_det_result.json kept
# only the length).  Verified against desc_det_result.json d0/d2/d4/d8/d9.
import json, os, re, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.stdout.reconfigure(line_buffering=True)

d = json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
evs = [e for e in d if e.get("tag") == "emit"]
print("emit events:", len(evs))


def take(i, n, sink0):
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
    if i < len(evs) and evs[i]["sink"] != prev_sink:
        msink = evs[i]["sink"]
        while i < len(evs) and evs[i]["sink"] == msink:
            i += 1

print("signings segmented:", len(signings))

ref = json.load(open(os.path.join(HERE, "desc_det_result.json")))
ok = True
out = []
for k, s in enumerate(signings):
    r = ref[k]
    same = (s["d0"] == r["d0"] and s["d2"] == r["d2"] and s["d4"] == r["d4"]
            and s["d8"] == r["d8"] and s["d9"] == r["d9"] and s["kind"] == r["kind"]
            and len(s["d10"]) == r["d10"])
    ok &= same
    b10 = b"".join(struct.pack(">I", v) for v in s["d10"])
    out.append({"k": k, "kind": s["kind"], "created_at": s["created_at"],
                "claims_hex": b10.hex(), "claims_len": len(b10)})
    print("S%d %-7s ca=%s len=%d match_desc_det=%s" % (k, s["kind"], s["created_at"], len(b10), same))
    print("    claims[:96] = %s" % b10[:96].decode("latin1"))
print("ALL MATCH desc_det_result:", ok)
json.dump(out, open(os.path.join(HERE, "claims_s012.json"), "w"), indent=1)
print("saved claims_s012.json")
