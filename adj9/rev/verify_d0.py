#!/usr/bin/env python3
"""Verify F.region against every nonzero fill_runs region.

The fill instant is cfg.(sec,usec) advanced by 4 ms, with a carry into seconds.
The capture corpus contains two normal head phases and one one-off alternate
scheduler phase; those are supplied from capture metadata, never selected from
the captured d0 bytes.  Every descriptor comparison is over all bytes.
"""
from __future__ import annotations

import glob
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import F  # noqa: E402

RUNS = HERE / "fill_runs"


def _descriptor(data: dict, va: int) -> bytes:
    for descriptor in data["descs"][0]:
        if descriptor["va"] == va:
            return bytes.fromhex(descriptor["hex"])
    raise KeyError(f"descriptor #{va} not found in {data.get('tag')}")


def _fill_V(cfg: dict) -> int:
    total_us = int(cfg["sec"]) * 1_000_000 + int(cfg["usec"]) + 4_000
    sec, usec = divmod(total_us, 1_000_000)
    return (sec ^ usec) & 0xFFFFFFFF


def _head_for_capture(data: dict) -> tuple[str, tuple[int, ...]]:
    cfg = data["cfg"]
    # These are the phase labels observed in the capture metadata.  They are
    # runtime state, not a function recoverable from V/pid/tid/second.
    if cfg.get("log_urandom_state") is True:
        return "FIRST", F.HEAD_FIRST
    if cfg.get("strvals", {}).get("android_id") is not None:
        return "RESIGN_ALT", F.HEAD_RESIGN_ALT
    return "RESIGN", F.HEAD_RESIGN


def _words(raw: bytes) -> list[int]:
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, len(raw), 4)]


def main() -> int:
    rows: list[tuple[str, str, str, int, int, int, str, str, str, bool]] = []
    for path in sorted(RUNS.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        region = data.get("region")
        if not isinstance(region, dict) or not data.get("descs"):
            continue
        actual_d0 = _descriptor(data, 0)
        # A gated zero region is intentionally outside this test.
        if int(region.get("W0", "0"), 16) == 0:
            continue

        # The harness descriptor-table indices are serializer positions, not
        # the logical region numbers used by F.py.  The normalized d2/d4 bytes
        # are the explicit region fields in each capture.
        actual_d2 = bytes.fromhex(str(region["d2"]).removeprefix("0x"))
        actual_d4 = b"".join(bytes.fromhex(x) for x in region["d4"])
        cfg = data["cfg"]
        V = _fill_V(cfg)
        pid = int(cfg["pid"])
        tid = int(cfg.get("tid", 0))
        phase, head = _head_for_capture(data)
        d0, d2, d4 = F.region(V, pid, tid, head=head)
        got_d0 = b"".join(word.to_bytes(4, "big") for word in d0)
        got_d2 = b"".join(word.to_bytes(4, "big") for word in [d2])
        got_d4 = b"".join(word.to_bytes(4, "big") for word in d4)

        # The task's structural law is checked independently of model equality.
        actual_words = _words(actual_d0)
        structure = (
            actual_words[0] == int(region["W0"], 16)
            and actual_words[1] == int(region["X"], 16)
            and actual_words[2:6] == [int(x, 16) for x in region["U"][:4]]
        )
        ok = got_d0 == actual_d0 and got_d2 == actual_d2 and got_d4 == actual_d4 and structure
        rows.append((
            path.name,
            phase,
            "PASS" if ok else "FAIL",
            V,
            pid,
            tid,
            got_d0[:24].hex(),
            got_d2.hex(),
            got_d4.hex(),
        ))

    print("file                    phase       result V       pid    tid    d0[0:24]                            d2        d4")
    print("----------------------- ----------- ------ -------- ----- ----- ---------------------------------- -------- ----------------------------------------------------------------")
    for name, phase, result, V, pid, tid, prefix, d2, d4 in rows:
        print(f"{name:23} {phase:11} {result:6} {V:08x} {pid:5d} {tid:5d} {prefix:34} {d2:8} {d4}")

    passed = sum(row[2] == "PASS" for row in rows)
    print(f"\n{passed}/{len(rows)} nonzero-region captures byte-exact (d0, d2, d4, prefix structure).")
    return 0 if rows and passed == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
