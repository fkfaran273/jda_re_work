"""fin_cmp.py — full-signing event comparison: emulator FinEx vs native capture.

Native reference: device/whcap_hits7.json records 0..NAT_END (signing A).
Sink-class mapping is built by first-appearance order on the native side and
matched to the emulator's streams:
  - the 9 field sinks <-> emu 0x5500000000+0x1000*i (slot i = va position)
  - 2fdee0 (merge workspace) <-> emu MAIN 0x5450001000
  - every other native sink <-> emu stream by first-appearance order.

Diffs the two event streams (sink_class, pos, val) and reports the first
divergence plus match counts. Saves rev/fin_cmp_out.json.
"""
import json, struct, sys, time

sys.path.insert(0, "C:/Users/Apps/Downloads/com.penti.app/adj9/rev")
from fin_vm2 import FinEx

HERE = "C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
DEV = "C:/Users/Apps/Downloads/com.penti.app/adj9/device"
NAT_END = int(sys.argv[2]) if len(sys.argv) > 2 else 22272
MAXSTEPS = int(sys.argv[1]) if len(sys.argv) > 1 else 2_000_000

D = json.load(open(HERE + "/fin_descs.json"))
SEED = D["target"]["second"]

# native field sinks by slot (from the corrected segmentation)
FIELD_SINKS = {}
nat_raw = json.load(open(DEV + "/whcap_hits7.json"))
evs = [e for e in nat_raw if e.get("tag") == "emit"]
seen = []
for i in range(147):
    s = evs[i]["sink"]
    if not seen or seen[-1] != s:
        seen.append(s)
for k, s in enumerate(seen):
    # the 9th field run is va position 9 (position 8 = the empty desc #1,
    # which never emits): field runs 0..7 -> slots 0..7, run 8 -> slot 9
    slot = k if k < 8 else 9
    FIELD_SINKS[s] = slot
# the interlude also writes the empty descs' sinks: 2fbed0 = slot 10 (#3)
FIELD_SINKS[[e for e in evs[352:356]][0]["sink"]] = 10
MERGE_SINK = [e for e in evs[147:22272] if True][0]["sink"]  # 2fdee0


def native_seq():
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
    nat = native_seq()
    json.dump(nat, open(HERE + "/nat_full.json", "w"))
    descs = [(d["len_dw"], 0, bytes.fromhex(d["data_hex"])) for d in D["descs"]]
    ex = FinEx(SEED, descs)
    t0 = time.time()
    status = ex.run(max_steps=MAXSTEPS)
    dt = time.time() - t0
    print("status=%s steps=%d nrand=%d (%.1fs) emu events=%d" %
          (status, ex.steps, ex.nrand, dt, len(ex.emit_trace)))

    # classify emu events
    slotmap = {0x5500000000 + 0x1000 * i: "F%d" % i for i in range(16)}
    xmap = {}      # native X-class -> emu stream va, by first appearance
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

    # align: find first divergence with a simple walk (native order == emu order)
    match = 0
    first_div = None
    for k in range(min(len(nat), len(emu))):
        if nat[k] != emu[k]:
            first_div = k
            break
        match += 1
    print("native events=%d  emu events=%d  matched=%d  first_div=%s"
          % (len(nat), len(emu), match, first_div))
    out = {
        "status": status, "steps": ex.steps, "nrand": ex.nrand, "secs": dt,
        "n_native": len(nat), "n_emu": len(emu), "matched": match,
        "first_div": first_div,
        "xmap": {hex(k & 0xFFFFFFFFFFFF): v for k, v in xmap.items()},
        "context": [],
    }
    k0 = first_div if first_div is not None else min(len(nat), len(emu))
    for j in range(max(0, k0 - 10), min(min(len(nat), len(emu)), k0 + 25)):
        out["context"].append([j, list(nat[j]), list(emu[j])])
    json.dump(out, open(HERE + "/fin_cmp_out.json", "w"), indent=1)
    for j in range(max(0, k0 - 6), min(min(len(nat), len(emu)), k0 + 16)):
        mark = "  <<<" if first_div is not None and j == first_div else ""
        print("  [%5d] nat %s   emu %s%s" % (j, nat[j], emu[j], mark))
    print("saved fin_cmp_out.json")


if __name__ == "__main__":
    main()
