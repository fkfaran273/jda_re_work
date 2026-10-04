"""Offline byte-exact verification of the adj9 FinEx body.

The capture files contain a 208-byte observation: the 192-byte VM envelope
(16-byte header plus 176-byte body) followed by a 16-byte capture suffix.
The suffix is not part of the envelope and is reported separately.
"""
from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from fin_vm2 import FinEx
from mint_pipeline import VA_ORDER, finex_mint


ENVELOPE_BYTES = 192
CAPTURE_BYTES = 208


def descriptors(capture):
    """Build FinEx's (len_dw, tag, raw_bytes) triples by build_idx.

    ``va`` is the serializer slot.  ``build_idx`` is the logical descriptor
    key, so selecting by list position as if va were build_idx is incorrect.
    A capture can end with a non-dword tail (env_val's #10 is 14 bytes).
    The VM descriptor still receives that claim NUL-padded to a whole dword;
    ``nbytes`` is the logical byte length, not the FinEx dword count.
    """
    by_build = {}
    for item in capture["descs"][0]:
        raw = bytes.fromhex(item["hex"]) if item.get("hex") else b""
        padded = raw + b"\x00" * (-len(raw) % 4)
        by_build[int(item["build_idx"])] = (
            len(padded) // 4,
            0,
            padded,
        )
    missing = sorted(set(VA_ORDER) - set(by_build))
    if missing:
        raise ValueError("missing build_idx descriptors: %s" % missing)
    return [by_build[i] for i in VA_ORDER]


def first_mismatch(got, expected):
    for i, (a, b) in enumerate(zip(got, expected)):
        if a != b:
            return i, a, b
    if len(got) != len(expected):
        return min(len(got), len(expected)), None, None
    return None


def run_one(path):
    capture = json.loads(path.read_text())
    expected_all = bytes.fromhex(capture["blob"])
    if len(expected_all) < ENVELOPE_BYTES:
        raise ValueError("capture blob is shorter than 192 bytes")
    expected = expected_all[:ENVELOPE_BYTES]

    # The non-production environment capture has #7 == 0: the native path
    # returns the previous signing envelope instead of entering FinEx.  It is
    # a real capture, but not a second VM execution.  Validate it against the
    # known base replay rather than manufacturing a new body from its stale
    # #10 payload.
    by_build = {int(x["build_idx"]): x for x in capture["descs"][0]}
    d7 = bytes.fromhex(by_build[7].get("hex") or "")
    if len(d7) >= 4 and int.from_bytes(d7[:4], "big") == 0:
        base_path = HERE / "fill_runs" / "base.json"
        base = bytes.fromhex(json.loads(base_path.read_text())["blob"])
        mismatch = first_mismatch(expected, base[:ENVELOPE_BYTES])
        return {
            "name": path.name,
            "ok": mismatch is None,
            "status": "gate-replay",
            "steps": 0,
            "nrand": 0,
            "match": mismatch is None,
            "mismatch": mismatch,
            "header_ok": expected[:16] == base[:16],
            "suffix": None,
            "got": expected,
        }

    descs = descriptors(capture)
    second = int(capture["srand"][0])
    got, info = finex_mint(descs, second, max_steps=40_000_000)
    mismatch = first_mismatch(got, expected)
    # The capture's trailing 16 bytes are outside the VM envelope.  Keep it
    # visible in the report, but do not count it as a VM mismatch.
    return {
        "name": path.name,
        "ok": mismatch is None and info["status"] == "exit-clean",
        "status": info["status"],
        "steps": info["steps"],
        "nrand": info["nrand"],
        "match": mismatch is None,
        "mismatch": mismatch,
        "header_ok": got[:16] == expected[:16],
        "suffix": None,
        "got": got,
    }


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    paths = [Path(x) if os.path.sep in x else HERE / "fill_runs" / x
             for x in argv]
    if not paths:
        paths = sorted((HERE / "fill_runs").glob("*.json"))
        paths = [p for p in paths if _eligible(p)]
    rows = []
    for path in paths:
        try:
            rows.append(run_one(path))
        except Exception as exc:
            rows.append({"name": path.name, "ok": False, "status": "EXCEPTION",
                         "steps": 0, "nrand": 0, "match": False,
                         "mismatch": None, "header_ok": False,
                         "suffix": None, "error": repr(exc)})

    print("capture                 status       steps   nrand  env  hdr  suffix")
    print("----------------------  -----------  -------  -----  ---  ---  ------")
    for row in rows:
        print("%-22s  %-11s  %7d  %5d  %s  %s  %s" % (
            row["name"], row["status"], row["steps"], row["nrand"],
            "PASS" if row["match"] else "FAIL",
            "PASS" if row["header_ok"] else "FAIL",
            "INFO" if row.get("suffix") is None else
            ("PASS" if row["suffix"] else "FAIL")))
        if "error" in row:
            print("  error: %s" % row["error"])
        elif row["mismatch"] is not None:
            i, got, expected = row["mismatch"]
            def byte_text(value):
                return ("%02x" % value) if isinstance(value, int) else "<short>"

            print("  first mismatch: byte %d (envelope offset 0x%x), got %s expected %s" %
                  (i, i, byte_text(got), byte_text(expected)))

    passed = sum(1 for row in rows if row["ok"])
    print("=== %d/%d captures byte-exact ===" % (passed, len(rows)))
    return 0 if passed == len(rows) else 1


def _eligible(path):
    try:
        data = json.loads(path.read_text())
        return ("blob" in data and "srand" in data and
                isinstance(data.get("descs"), list) and data["descs"] and
                isinstance(data["descs"][0], list))
    except Exception:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
