#!/usr/bin/env python3
"""Audit/decode attempt for an adj9 envelope body.

The FinEx implementation in this tree is an encoder: FinEx(seed, descriptors)
executes the lifted writer and emits the 48-word envelope stream.  It has no
input/body mode, and the genuine SAZ does not contain the per-signing region
words.  This script keeps the negative result reproducible and, with --probe,
runs independent FinEx oracle probes showing which descriptor words affect the
body.  It deliberately does not invent a seed or descriptor recovery.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "adj9_tool"))
sys.path.insert(0, str(HERE))


def genuine_units(path: Path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    for unit in doc["units"]:
        blob = bytes.fromhex(unit["blob_hex"])
        yield unit, blob


def show(unit, blob):
    assert len(blob) == 192, len(blob)
    hdr, body = blob[:16], blob[16:]
    print(f"session={unit['session']} path={unit['path']} "
          f"second={unit['signing_second']} claim_len={unit['claim_unpadded_length']}")
    print(f"  header={hdr.hex()}")
    print(f"  body  ={body.hex()}")
    print(f"  body_words={' '.join(f'{x:08x}' for x in struct.unpack('>44I', body))}")
    try:
        from adj9_signer import make_header
        expected = make_header(int(unit["signing_second"]))
        print(f"  header_law={'PASS' if expected == hdr else 'FAIL'} expected={expected.hex()}")
    except Exception as exc:
        print(f"  header_law=unavailable ({exc})")


def probe():
    """Run controlled FinEx calls; this is an encoder sensitivity experiment."""
    import mint_pipeline as mp
    doc = json.loads((HERE / "saz_blobs.json").read_text(encoding="utf-8"))
    unit = doc["units"][0]
    claims = mp.claims_from_wire(unit["params"], "session")
    second = int(unit["signing_second"])

    def run(d0, d2, d4):
        descs, _ = mp.build_descriptors(
            claims, "session",
            mp._to_desc_bytes(d0, 144, "d0"),
            mp._to_desc_bytes(d2, 4, "d2"),
            mp._to_desc_bytes(d4, 32, "d4"),
        )
        blob, info = mp.finex_mint(descs, second, max_steps=30_000_000)
        assert info["status"] == "exit-clean", info
        return blob[16:]

    z36, z8 = [0] * 36, [0] * 8
    base = run(z36, 0, z8)
    d4 = run(z36, 0, [0xA5A5A5A5] + z8[1:])
    d2 = run(z36, 1, z8)
    d0 = run([1] + z36[1:], 0, z8)
    print("probe body lengths:", *(len(x) for x in (base, d4, d2, d0)))
    print("d4-only changes body:", d4 != base)
    print("d2-only changes body:", d2 != base)
    print("d0-only changes body:", d0 != base)
    print("base body:", base.hex())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, default=HERE / "saz_blobs.json")
    ap.add_argument("--probe", action="store_true",
                    help="run controlled FinEx encoder sensitivity probes")
    args = ap.parse_args()
    for unit, blob in genuine_units(args.input):
        show(unit, blob)
    print("decode result: unavailable from the existing FinEx API")
    print("reason: FinEx is writer-only; no inverse/read mode or body hydration exists.")
    print("reason: SAZ stores only the 176-byte output body, not d0/d2/d4 or the 32-bit seed.")
    if args.probe:
        probe()


if __name__ == "__main__":
    main()
