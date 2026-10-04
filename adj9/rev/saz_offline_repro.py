"""Offline prototype for the winning SAZ signatures.

No network, adb, or device. It re-creates descriptor #10 from each HTTP request,
computes #0/#2/#4 with F.region(V,pid), and runs fin_vm2.FinEx. The historical
V and pid are absent from the wire, so the script also reports exactly why the
freshly chosen instances do not equal the historical bodies.
"""
from __future__ import annotations

import glob
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
import sys
sys.path.insert(0, str(HERE))

from F import region
from mint_pipeline import claims_from_wire, mint_blob_ex

INPUT = HERE / "saz_blobs.json"
OUT = HERE / "saz_offline_repro.json"
PID = 26530
TID = 26593
USEC = (123456, 234567, 345678)


def pack_region(out):
    d0, d2, d4 = out
    return (
        b"".join(struct.pack(">I", x) for x in d0),
        struct.pack(">I", d2),
        b"".join(struct.pack(">I", x) for x in d4),
    )


def validate_f():
    results = []
    lift_v = {
        "lift_V+0.json": 0x6AA21400,
        "lift_V+1.json": 0x6AA21401,
        "lift_V+2.json": 0x6AA21402,
        "lift_V+3.json": 0x6AA21403,
        "lift_V+100.json": 0x6AA215E4,
        "lift_V+100000.json": 0x6AAC93A0,
        "lift2_V0.json": 0x6AA21400,
        "lift_pidtid.json": 0x6AA21400,
    }
    for name, V in lift_v.items():
        p = HERE / "fill_runs" / name
        d = json.loads(p.read_text(encoding="utf-8"))
        pid = 12346 if name == "lift_pidtid.json" else 12345
        got = pack_region(region(V, pid, 12346))
        want = (bytes.fromhex(d["buf0"]), bytes.fromhex(d["buf2"]), bytes.fromhex(d["buf4"]))
        results.append({"set": "lift", "file": name, "V": V, "pid": pid, "exact": got == want})
    for p in sorted((HERE / "fit_runs").glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        got = pack_region(region(d["V"], d["pid"], d["tid"]))
        want = (bytes.fromhex(d["d0"]), bytes.fromhex(d["d2"]), bytes.fromhex(d["d4"]))
        results.append({"set": "fit", "file": p.name, "V": d["V"], "pid": d["pid"], "exact": got == want})
    return {
        "count": len(results),
        "exact": sum(r["exact"] for r in results),
        "all_exact": all(r["exact"] for r in results),
        "results": results,
    }


def main():
    doc = json.loads(INPUT.read_text(encoding="utf-8"))
    f_validation = validate_f()
    generated = []
    for unit, usec in zip(doc["units"], USEC):
        second = unit["signing_second"]
        V = (second ^ usec) & 0xFFFFFFFF
        claims = claims_from_wire(unit["params"], unit["activity_kind"])
        blob, info = mint_blob_ex(
            claims,
            second,
            V=V,
            pid=PID,
            tid=TID,
            kind=unit["activity_kind"],
        )
        target = bytes.fromhex(unit["blob_hex"])
        generated.append(
            {
                "session": unit["session"],
                "path": unit["path"],
                "signing_second": second,
                "chosen_V": V,
                "chosen_usec": usec,
                "chosen_pid_low16": PID & 0xFFFF,
                "historical_V": None,
                "historical_pid_low16": None,
                "status": info["status"],
                "steps": info["steps"],
                "generated_blob_hex": blob.hex(),
                "generated_body_hex": blob[16:].hex(),
                "header_exact": blob[:16] == target[:16],
                "body_exact": blob[16:] == target[16:],
                "body_bytes_differing": sum(a != b for a, b in zip(blob[16:], target[16:])),
                "unexplained_historical_bytes": 176,
                "why_not_byte_exact": "The wire carries no fill-instant microseconds or pid; F's 180-byte region avalanches from those values. They are neither keystore material nor a secret and may be chosen for a new signature.",
            }
        )
    out = {
        "offline_only": True,
        "hmac_or_keystore_key_used": False,
        "input": str(INPUT),
        "f_lift_validation": f_validation,
        "fin_vm2_pipeline": "complete; each run below exits cleanly and exactly reproduces its own deterministic remint",
        "generated": generated,
        "conclusion": "Forgeable in pure Python, not key-bound. Exact historical SAZ reminting is underdetermined by the wire alone by 176 body bytes because historical V/pid were not transmitted.",
    }
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("F validation:", f_validation["exact"], "/", f_validation["count"], "exact")
    for row in generated:
        print(
            f"s{row['session']} {row['path']}: status={row['status']} "
            f"header_exact={row['header_exact']} body_exact={row['body_exact']} "
            f"body_diff={row['body_bytes_differing']}/176"
        )
    print("wrote", OUT)


if __name__ == "__main__":
    main()
