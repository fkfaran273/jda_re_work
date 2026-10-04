"""R4 harness: run vm_final.Ex with golden_fresh real values + unknowns.
Reports: exit status/steps, dispatch PCs visited, queue depths, nrand.
Usage: python r4_harness.py [sweep]
"""
import sys, struct, json
sys.path.insert(0, ".")
from vm_final import Ex

G = {k: v for k, v in json.load(open("golden_fresh.json")).items()}
TS = G["nsign"][0]
H = bytes.fromhex([l for l in G["nsign_in"][1].splitlines() if l.startswith("arg3_hex=")][0].split("=")[1])
CERT_SHA1 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
SEC = TS // 1000
LENS = (36, 0, 1, 1, 8, 1, 1, 1, 4, 5, 4)

def build(unknowns):
    """unknowns: dict idx -> bytes (len must match LENS). Knowns filled real."""
    descs = []
    for i, ln in enumerate(LENS):
        if i == 4: data = H
        elif i == 9: data = CERT_SHA1
        elif i == 5: data = struct.pack(">I", 31)
        elif i in unknowns: data = unknowns[i]
        else: data = bytes(4 * ln)
        assert len(data) == 4 * ln, (i, len(data), ln)
        descs.append((ln, 0, data))
    return descs

def run(descs, seed=SEC):
    ex = Ex(seed=seed, descs=descs)
    st = ex.run()
    # dispatch PCs: any pc in 0x100554..0x100700 visited?
    disp = sorted(pc for pc in ex._pc_hist if 0x100554 <= pc <= 0x100700)
    return {"status": st, "steps": ex.steps, "nrand": ex.nrand,
            "queues": {hex(k): len(v) for k, v in ex.queues.items()},
            "disp": [hex(p) for p in disp[:12]], "ndisp": len(disp)}

if __name__ == "__main__":
    base = run(build({}))
    print("BASELINE zeros:", base)
    if len(sys.argv) > 1 and sys.argv[1] == "sweep":
        cands = {"ts_sec": SEC, "api": 31, "mapsize": 50, "count11": 11,
                 "len36": 36, "len62": 62, "len48": 48, "one": 1, "zero": 0,
                 "c0": 0xC0, "b0": 176, "hlen32": 32, "sha20": 20}
        for idx in (2, 6, 7):
            for name, val in cands.items():
                r = run(build({idx: struct.pack(">I", val)}))
                if (r["steps"], r["ndisp"]) != (base["steps"], base["ndisp"]):
                    print("idx%d=%s(%d): steps %d->%d ndisp %d->%d %s" % (
                        idx, name, val, base["steps"], r["steps"],
                        base["ndisp"], r["ndisp"], r["status"]))
        print("sweep done (only CHANGES vs baseline printed)")
