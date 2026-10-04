"""fin_mapcmp.py — final-state (last-write-wins) comparison + blob window check.

The native merge-sink chain events embed uninitialized heap garbage in their
intermediate LENQ readbacks (native offs array realloc tail); each 4-byte
chain completes so the FINAL per-position values are pure. This script:
  1. builds last-write maps per sink class for native (records 0..NAT_END)
     and emulator;
  2. diffs the maps;
  3. checks the output-sink [0..48) window against the target blob (4/4
     header + 44/44 body).
"""
import json, struct, sys

sys.path.insert(0, "C:/Users/Apps/Downloads/com.penti.app/adj9/rev")
from fin_vm2 import FinEx

HERE = "C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
DEV = "C:/Users/Apps/Downloads/com.penti.app/adj9/device"
NAT_END = int(sys.argv[2]) if len(sys.argv) > 2 else 22272
MAXSTEPS = int(sys.argv[1]) if len(sys.argv) > 1 else 8_000_000

D = json.load(open(HERE + "/fin_descs.json"))
SEED = D["target"]["second"]
BLOB = bytes.fromhex(D["target"]["blob_hex"])
TGT = [struct.unpack_from(">I", BLOB, 4 * i)[0] for i in range(48)]

nat_raw = json.load(open(DEV + "/whcap_hits7.json"))
evs = [e for e in nat_raw if e.get("tag") == "emit"]
seen = []
for i in range(147):
    s = evs[i]["sink"]
    if not seen or seen[-1] != s:
        seen.append(s)
FIELD_SINKS = {}
for k, s in enumerate(seen):
    FIELD_SINKS[s] = k if k < 8 else 9
FIELD_SINKS[evs[352]["sink"]] = 10           # 2fbed0 = slot 10 (#3's sink)
MERGE_SINK = evs[147]["sink"]


def nat_events():
    out = []
    for i in range(0, NAT_END):
        e = evs[i]
        s = e["sink"]
        if s in FIELD_SINKS:
            cls = "F%d" % FIELD_SINKS[s]
        elif s == MERGE_SINK:
            cls = "M"
        else:
            cls = "X:%s" % s[-6:]
        out.append((cls, int(e["pos"], 16), int(e["val"], 16)))
    return out


def main():
    nat = nat_events()
    descs = [(d["len_dw"], 0, bytes.fromhex(d["data_hex"])) for d in D["descs"]]
    ex = FinEx(SEED, descs)
    import time
    t0 = time.time()
    status = ex.run(max_steps=MAXSTEPS)
    dt = time.time() - t0
    print("status=%s steps=%d nrand=%d (%.1fs) emu events=%d (native=%d)"
          % (status, ex.steps, ex.nrand, dt, len(ex.emit_trace), len(nat)))

    slotmap = {0x5500000000 + 0x1000 * i: "F%d" % i for i in range(16)}
    xmap = {}
    emu = []
    for (sva, n, v) in ex.emit_trace:
        sva &= 0xFFFFFFFFFFFF
        if sva in slotmap:
            cls = slotmap[sva]
        elif sva == 0x5450001000:
            cls = "M"
        else:
            cls = xmap.get(sva)
            if cls is None:
                cls = "X#%d" % len(xmap)
                xmap[sva] = cls
        emu.append((cls, n & 0xFFFFFFFF, v & 0xFFFFFFFF))

    def lastmap(seq):
        m = {}
        for (c, p, v) in seq:
            m[(c, p)] = v
        return m
    nm, em = lastmap(nat), lastmap(emu)
    keys = set(nm) | set(em)
    diffs = []
    for k in sorted(keys):
        a, b = nm.get(k), em.get(k)
        if a != b:
            diffs.append((k, a, b))
    print("\nfinal-state map: native keys=%d emu keys=%d  DIFFS=%d"
          % (len(nm), len(em), len(diffs)))
    for (k, a, b) in diffs[:40]:
        print("   %s pos=%-5d nat=%s emu=%s" % (k[0], k[1],
              "%08x" % a if a is not None else "-", "%08x" % b if b is not None else "-"))
    if len(diffs) > 40:
        print("   ... %d more" % (len(diffs) - 40))

    # blob window on every sink class of the emulator
    print("\nblob window check (last-write maps, [0..48)):")
    best = (0, None)
    per = {}
    from collections import defaultdict
    bycls = defaultdict(dict)
    for (c, p), v in em.items():
        bycls[c][p] = v
    for c, m in sorted(bycls.items()):
        cnt = sum(1 for i in range(48) if m.get(i) == TGT[i])
        per[c] = cnt
        if cnt > best[0]:
            best = (cnt, c)
        if cnt:
            print("   %-6s %d/48" % (c, cnt))
    print("BEST: %s %d/48" % (best[1], best[0]))

    # also the raw event-stream 1:1 match with garbage tolerance:
    # skip native events that are chain intermediates (same pos+class rewritten
    # later with a value that differs only in bits the final fixes). Simple
    # proxy: count how many native events have an exact (class,pos,value) twin
    # in the emu stream.
    eset = set(emu)
    twin = sum(1 for e in nat if e in eset)
    print("\nnative events with exact twin in emu: %d/%d" % (twin, len(nat)))

    json.dump({
        "status": status, "steps": ex.steps, "nrand": ex.nrand,
        "n_native": len(nat), "n_emu": len(emu),
        "map_diffs": len(diffs),
        "diff_sample": [[list(k), a, b] for (k, a, b) in diffs[:200]],
        "blob_windows": per, "best": best, "twin": twin,
        "xmap": {hex(k & 0xFFFFFFFFFFFF): v for k, v in xmap.items()},
    }, open(HERE + "/fin_mapcmp_out.json", "w"), indent=1)
    print("saved fin_mapcmp_out.json")


if __name__ == "__main__":
    main()
