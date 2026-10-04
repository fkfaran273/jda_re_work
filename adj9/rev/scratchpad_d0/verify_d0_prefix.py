#!/usr/bin/env python3
"""Audit the seed-derived d0 tail and the anomalous 12-halfword prefix.

This script does not modify the signer model.  It:
  * verifies d2 and d4 against every supplied capture;
  * demonstrates that the model's 72 fixed x1 values do not match the fresh rows;
  * inverts the XOR whitener for the first 12 captured halfwords, recovering the
    unique effective masks/x1 values in the 8-bit mask domain;
  * replays d0 using those recovered values and verifies all 11 rows;
  * maps the relevant RVAs to file offsets and finds direct BL xrefs.

The recovered prefix is a property of the captured d0 bytes, not a proven
function of seed S.  The native 0x143a38 call hard-codes x1 = 0x40 | (i & 7).
"""
from __future__ import annotations

import importlib.util
import json
import struct
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Apps\Downloads\com.penti.app\adj9")
REV = ROOT / "rev"
LIB = ROOT.parent / "extracted" / "arm64" / "lib" / "arm64-v8a" / "libsigner.so"
MODEL = ROOT / "adj9_tool" / "adj9_signer.py"
FRESH = ROOT / "device" / "rows_full.json"
OLD = REV / "pair_h3.json"

sys.path.insert(0, str(REV))
from elf import ELF  # noqa: E402

spec = importlib.util.spec_from_file_location("adj9_signer_audit", MODEL)
assert spec and spec.loader
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


def d4_bytes(seed: int) -> bytes:
    return b"".join(w.to_bytes(4, "big") for w in model._d4_words(seed))


def source_words(d4b: bytes) -> list[int]:
    if len(d4b) != 32:
        raise ValueError("d4 must be 32 bytes")
    return [int.from_bytes(d4b[i : i + 2], "little") for i in range(16, 32, 2)]


def recover_x1(captured_d0: bytes, seed: int) -> tuple[int, ...]:
    """Invert one captured halfword to the unique odd 8-bit selector mask.

    whitener_word(x1) uses mask=(2*x1+3)&0xff.  x1=((mask-3)//2).
    Restricting mask to 8 bits is not an assumption about how d0 was made; it
    is the exact domain used by the reference whitener for these x1 values.
    """
    src = source_words(d4_bytes(seed))
    by_value: dict[int, list[int]] = {}
    for mask in range(1, 256, 2):
        value = 0
        for bit in range(8):
            if (mask >> bit) & 1:
                value ^= src[7 - bit]
        by_value.setdefault(value, []).append(mask)
    result: list[int] = []
    for j in range(12):
        value = int.from_bytes(captured_d0[2 * j : 2 * j + 2], "little")
        masks = by_value.get(value, [])
        if len(masks) != 1:
            raise ValueError(f"halfword {j}: expected one mask, got {masks!r}")
        mask = masks[0]
        result.append((mask - 3) // 2)
    return tuple(result)


def d0_from_prefix(seed: int, prefix_x1: tuple[int, ...]) -> bytes:
    """Drop-in d0 construction when the effective first-12 x1 values are known."""
    if len(prefix_x1) != 12:
        raise ValueError("prefix_x1 must contain 12 values")
    src = source_words(d4_bytes(seed))
    values = [model._whitener_word(0x40 + (i & 7), src) for i in range(72)]
    for i, x1 in enumerate(prefix_x1):
        values[i] = model._whitener_word(x1, src)
    raw = b"".join(v.to_bytes(2, "little") for v in values)
    return raw


def fixed_model_d0(seed: int) -> bytes:
    words = model._d0_words(model._d4_words(seed))
    return b"".join(w.to_bytes(4, "big") for w in words)


def d2_from_seed(seed: int) -> bytes:
    return seed.to_bytes(4, "little")


def direct_bl_xrefs(elf: ELF, target: int) -> list[int]:
    out: list[int] = []
    for sec in elf.sections:
        if not (sec["flags"] & 4):  # SHF_EXECINSTR
            continue
        data = elf.section_bytes(sec["name"])
        for off in range(0, len(data) - 3, 4):
            word = struct.unpack_from("<I", data, off)[0]
            if word & 0xFC000000 != 0x94000000:  # BL imm26
                continue
            imm = word & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            pc = sec["addr"] + off
            if pc + (imm << 2) == target:
                out.append(pc)
    return sorted(out)


def load_rows() -> list[dict]:
    rows: list[dict] = []
    fresh = json.loads(FRESH.read_text())["rows"]
    for row in fresh:
        rows.append(
            {
                "kind": "fresh",
                "label": str(row["sign_id"]),
                "seed": int(row["S"]),
                "second": row.get("second"),
                "d0": bytes.fromhex(row["desc"]["0"]["hex"]),
                "d2": bytes.fromhex(row["desc"]["2"]["hex"]),
                "d4": bytes.fromhex(row["desc"]["4"]["hex"]),
            }
        )
    for row in json.loads(OLD.read_text()):
        d2 = bytes.fromhex(row["d2"])
        rows.append(
            {
                "kind": "old",
                "label": str(row["i"]),
                "seed": struct.unpack("<I", d2)[0],
                "second": row.get("second"),
                "d0": bytes.fromhex(row["d0"]),
                "d2": d2,
                "d4": bytes.fromhex(row["d4"]),
            }
        )
    return rows


def main() -> int:
    rows = load_rows()
    elf = ELF(str(LIB))
    print(f"library: {LIB}")
    print(f"size:    {len(elf.data):#x}")
    for rva in (0x1437EC, 0x143A28, 0x143B20, 0x144074, 0x1441E4, 0x144214, 0x12B74):
        off = elf.vaddr_to_off(rva)
        print(f"RVA {rva:#x} -> file offset {off:#x}")
    print("direct BL xrefs to 0x144074:", [hex(x) for x in direct_bl_xrefs(elf, 0x144074)])
    print("direct BL xrefs to 0x144214:", [hex(x) for x in direct_bl_xrefs(elf, 0x144214)])
    print()

    d2_ok = d4_ok = recovered_ok = 0
    fixed_ok = 0
    for row in rows:
        seed = row["seed"]
        prefix = recover_x1(row["d0"], seed)
        replay = d0_from_prefix(seed, prefix)
        checks = {
            "d2": d2_from_seed(seed) == row["d2"],
            "d4": d4_bytes(seed) == row["d4"],
            "recovered_d0": replay == row["d0"],
            "fixed_model_d0": fixed_model_d0(seed) == row["d0"],
        }
        d2_ok += checks["d2"]
        d4_ok += checks["d4"]
        recovered_ok += checks["recovered_d0"]
        fixed_ok += checks["fixed_model_d0"]
        print(
            f"{row['kind']:5} {row['label']:>2} S={seed:08x} "
            f"second={row['second']} prefix={tuple(hex(x) for x in prefix)} "
            f"d0={'OK' if checks['recovered_d0'] else 'FAIL'} "
            f"fixed={'OK' if checks['fixed_model_d0'] else 'FAIL'}"
        )

    print()
    print(f"d2:        {d2_ok}/{len(rows)}")
    print(f"d4:        {d4_ok}/{len(rows)}")
    print(f"d0 fixed:  {fixed_ok}/{len(rows)}")
    print(f"d0 solved: {recovered_ok}/{len(rows)}")
    return 0 if d2_ok == d4_ok == recovered_ok == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
