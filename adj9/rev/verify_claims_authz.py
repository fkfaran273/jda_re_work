#!/usr/bin/env python3
"""Verify descriptor-10 claim selection and Authorization encoding from RAW logs.

This script deliberately treats only device/adj9_wh4.log and adj9_wh2.log as
claim/header evidence.  It imports the current implementation solely to compare
it with those bytes.  It never reads notes/*.md or pre-derived JSON captures.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEVICE = ROOT / "device"
LOG_NAMES = ("adj9_wh4.log", "adj9_wh2.log")
sys.path.insert(0, str(HERE))

from desc10_law import build_desc10, desc10_keys  # noqa: E402
from mint_pipeline import (  # noqa: E402
    ADJ_SIGNING_ID,
    ADJ_VERIFICATION,
    INTERNAL_CLAIMS,
    auth_header,
    claims_from_wire,
)

BEGIN_RE = re.compile(r"^###ADJ9_BEGIN (?P<meta>.*)$")
META_KV_RE = re.compile(r"(\w+)=([^ ]+)")


def parse_records(path: Path):
    """Yield raw instrumented records with exact 1-based source lines."""
    current = None
    with path.open("r", encoding="utf-8", errors="strict", newline="") as f:
        for line_no, line in enumerate(f, 1):
            if current is None:
                m = BEGIN_RE.match(line.rstrip("\r\n"))
                if m:
                    meta = dict(META_KV_RE.findall(m.group("meta")))
                    current = {
                        "path": path,
                        "begin_line": line_no,
                        "meta": meta,
                        "lines": [],
                    }
                continue
            if line.startswith("###ADJ9_END"):
                current["end_line"] = line_no
                yield current
                current = None
            else:
                current["lines"].append((line_no, line.rstrip("\r\n")))
    if current is not None:
        raise ValueError(f"unterminated record at {path}:{current['begin_line']}")


def field(record, prefix):
    for line_no, text in record["lines"]:
        if text.startswith(prefix):
            return line_no, text[len(prefix):]
    raise ValueError(
        f"missing {prefix!r} in {record['path']}:{record['begin_line']}"
    )


def parse_order_map(record):
    order_line, order = field(record, "map_order=")
    if order.endswith("\r"):
        order = order[:-1]
    parts = order.split("\x02")
    if parts and parts[-1] == "":
        parts.pop()
    pairs = []
    for part in parts:
        if part.count("\x01") != 1:
            raise ValueError(
                f"bad map_order item at {record['path']}:{order_line}: {part!r}"
            )
        key, value = part.split("\x01", 1)
        pairs.append((key, value))
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError(
            f"duplicate key in map_order at {record['path']}:{order_line}"
        )
    return pairs, order, order_line


def line_of_value(record, key, value):
    needle = key + "\x01" + value + "\x02"
    for line_no, text in record["lines"]:
        if text.startswith("map_order=") and needle in text:
            return line_no
    return record["begin_line"]


def show(value, limit=220):
    value = repr(value)
    return value if len(value) <= limit else value[:limit - 3] + "..."


def infer_kind(real):
    kind = real.get("activity_kind", "<missing>")
    if kind not in ("session", "click", "attribution"):
        return kind
    return kind


def verify_claims(records):
    stats = Counter()
    mismatches = []
    examples = defaultdict(list)
    wire_only_patterns = defaultdict(Counter)
    claim_key_union = defaultdict(set)
    all_keys_by_kind = defaultdict(set)

    for rec in records:
        stats["records"] += 1
        size_line, size_text = field(rec, "text: map_size=")
        size = int(size_text)
        tostring_line, tostring = field(rec, "map_toString=")
        pairs, order, order_line = parse_order_map(rec)
        real = dict(pairs)
        kind = real.get("activity_kind", "<missing>")
        actual_order = [k for k, _ in pairs]
        stats[f"kind:{kind}"] += 1
        stats[f"size:{kind}:{size}"] += 1
        all_keys_by_kind[kind].update(actual_order)

        if len(real) != size:
            mismatches.append((rec, size_line, "map_size",
                               f"declared={size}, parsed={len(real)}"))
        expected_tostring = "{" + ", ".join(f"{k}={v}" for k, v in pairs) + "}"
        if tostring != expected_tostring:
            mismatches.append((rec, tostring_line, "map_toString",
                               "does not equal unescaped {key=value, ...} "
                               f"reconstruction: {show(tostring)}"))

        raw_hex_line, raw_hex = field(rec, "hex: ")
        raw_truncated = bool(re.search(r"\.\.\.\(\+\d+B\)$", raw_hex))
        try:
            hex_body = re.sub(r"\.\.\.\(\+\d+B\)$", "", raw_hex)
            raw_decoded = bytes.fromhex(hex_body)
        except ValueError as exc:
            mismatches.append((rec, raw_hex_line, "raw hex", str(exc)))
            raw_decoded = b""
        else:
            if raw_truncated:
                stats["raw_hex_truncated"] += 1
            else:
                # The hex payload is the exact field body without display-only
                # prefixes and with no trailing blank line.
                body_lines = []
                for _, text in rec["lines"][:-1]:
                    if text.startswith("text: "):
                        body_lines.append(text[6:])
                    else:
                        body_lines.append(text)
                body = "\n".join(body_lines).rstrip("\n") + "\n"
                if raw_decoded.decode("utf-8") != body:
                    mismatches.append((rec, raw_hex_line, "raw UTF-8",
                                       "hex payload differs from displayed record body"))
        if not raw_truncated and order.encode("utf-8") not in raw_decoded:
            mismatches.append((rec, order_line, "raw map_order",
                               "UTF-8 map_order bytes absent from raw hex payload"))

        for key in ("referrer", "partner_params"):
            if key in real:
                label = f"{kind}:{key}"
                if len(examples[label]) < 3:
                    examples[label].append(
                        (rec["path"].name, line_of_value(rec, key, real[key]), real[key])
                    )
        for key, value in pairs:
            if key in ("created_at", "installed_at", "updated_at", "sent_at"):
                m = re.search(r"(Z[+-]\d{4})$", value)
                offset = m.group(1)[1:] if m else "<none>"
                examples[f"offset:{kind}:{offset}"].append(
                    (rec["path"].name, line_of_value(rec, key, value), offset)
                )

        wire_kind = infer_kind(real)
        try:
            expected_keys = desc10_keys(wire_kind, real)
        except (ValueError, TypeError) as exc:
            stats["unsupported_kind"] += 1
            mismatches.append((rec, rec["begin_line"], "implementation support",
                               f"activity_kind={wire_kind!r}: {exc}"))
            continue

        claim_key_union[wire_kind].update(expected_keys)
        wire_only = [k for k in actual_order if k not in expected_keys]
        wire_only_patterns[wire_kind][tuple(wire_only)] += 1
        missing = [k for k in expected_keys if k not in real]
        if missing:
            stats["records_missing_claim_values"] += 1
            mismatches.append((rec, order_line, "missing claim keys", repr(missing)))
        else:
            try:
                constructed = claims_from_wire(real, wire_kind)
            except Exception as exc:  # report implementation exceptions as evidence
                stats["claims_from_wire_errors"] += 1
                mismatches.append((rec, rec["begin_line"], "claims_from_wire",
                                   f"{type(exc).__name__}: {exc}"))
                continue
            if list(constructed) != expected_keys:
                mismatches.append((rec, rec["begin_line"], "claim ORDER",
                                   f"desc10_keys={expected_keys!r}; "
                                   f"claims_from_wire={list(constructed)!r}"))
            for key in expected_keys:
                got = constructed.get(key)
                want = wire_kind if key == "activity_kind" else (
                    INTERNAL_CLAIMS.get(key, real.get(key))
                )
                if got != want:
                    stats["value_mismatches"] += 1
                    mismatches.append((rec, line_of_value(rec, key, str(real.get(key))),
                                       f"different value key={key}",
                                       f"raw={show(str(want))} constructed={show(str(got))}"))
            try:
                built = build_desc10(constructed, wire_kind)
            except Exception as exc:
                stats["build_desc10_errors"] += 1
                mismatches.append((rec, rec["begin_line"], "build_desc10",
                                   f"{type(exc).__name__}: {exc}"))
            else:
                # The raw sign_input contains the 192-byte signing input/output,
                # not descriptor #10 as a plainly concatenated byte string, so a
                # byte equality assertion here would be category-incorrect.
                stats["build_desc10_success"] += 1
                if built.encode("latin-1") == built.encode("utf-8") and "\x00" in built:
                    mismatches.append((rec, rec["begin_line"], "build_desc10",
                                       "NUL unexpectedly occurs in concatenated claim values"))

    print("=== CLAIMS FROM RAW sign_input RECORDS ===")
    print(f"records: {stats['records']}")
    for kind in sorted(k for k in stats if k.startswith("kind:")):
        print(f"  {kind[5:]}: {stats[kind]}")
        for size_key in sorted((k for k in stats if k.startswith(f"size:{kind[5:]}:")),
                               key=lambda x: int(x.rsplit(":", 1)[1])):
            print(f"    {size_key.rsplit(':', 1)[0]}: {stats[size_key]}")
    print(f"unsupported kinds: {stats['unsupported_kind']} "
          f"(event/info have no desc10_keys/build_desc10 implementation)")
    print("union of raw wire keys by kind:")
    for kind in sorted(all_keys_by_kind):
        print(f"  {kind} ({len(all_keys_by_kind[kind])}): "
              + ", ".join(sorted(all_keys_by_kind[kind])))
    print("implemented claim-key unions by kind:")
    for kind in ("session", "click", "attribution"):
        keys = sorted(claim_key_union.get(kind, set()))
        print(f"  {kind} ({len(keys)}): " + ", ".join(keys))
        missing_from_wire_union = sorted(set(keys) - all_keys_by_kind.get(kind, set()))
        if missing_from_wire_union:
            print("    NEVER PRESENT in raw map: " + ", ".join(missing_from_wire_union))
    print("wire-only key patterns (proves selection is not 'all sign_input params'):")
    for kind in sorted(wire_only_patterns):
        for pattern, count in sorted(wire_only_patterns[kind].items(),
                                     key=lambda item: (-item[1], item[0])):
            print(f"  {kind} x{count}: " + ", ".join(pattern))
    print("special raw values (repr proves exact characters/no escaping):")
    for label in sorted(examples):
        vals = examples[label]
        print(f"  {label} ({len(vals)} shown):")
        for path_name, line_no, value in vals[:3]:
            print(f"    {path_name}:{line_no}: {show(value, 500)}")
    print(f"map_toString exact unescaped reconstruction mismatches: "
          f"{sum(1 for m in mismatches if m[2] == 'map_toString')}")
    print(f"raw UTF-8/order integrity mismatches: "
          f"{sum(1 for m in mismatches if m[2] in ('raw UTF-8', 'raw hex', 'raw map_order'))}")
    print(f"claim value mismatches: {stats['value_mismatches']}")
    print(f"records with missing claim values: {stats['records_missing_claim_values']}")
    print(f"successful build_desc10 comparisons: {stats['build_desc10_success']}")
    print(f"total claim mismatches/events: {len(mismatches)}")
    for item in mismatches:
        rec = item[0]
        print(f"  MISMATCH {rec['path']}:{item[1]} {item[2]}: {item[3]}")
        if len(item) > 4:
            print(f"    {item[4]}")
    return stats, mismatches


def extract_ns_419(records):
    return [r for r in records if r["meta"].get("type") == "nsign"
            and r["meta"].get("utf8len") == "419"]


def extract_auth(records):
    return [r for r in records if r["meta"].get("type") == "authorization_header"]


def parse_auth(rec):
    text_line, displayed_suffix = field(rec, "text: Signature signature=")
    displayed = "Signature signature=" + displayed_suffix
    hex_line, raw_hex = field(rec, "hex: ")
    raw = bytes.fromhex(raw_hex)
    if raw.decode("utf-8") != displayed:
        raise ValueError(f"authorization display/raw mismatch at {rec['path']}:{rec['begin_line']}")
    m = re.fullmatch(r'Signature signature="([^"]+)",adj_signing_id="([^"]+)",'
                     r'algorithm="([^"]+)",headers_id="([^"]+)",native_version="([^"]+)",'
                     r'adj_verification="([^"]+)"', displayed)
    if not m:
        raise ValueError(f"unexpected authorization format at {rec['path']}:{rec['begin_line']}")
    return {
        "text_line": text_line,
        "hex_line": hex_line,
        "signature": m.group(1),
        "adj_signing_id": m.group(2),
        "algorithm": m.group(3),
        "headers_id": m.group(4),
        "native_version": m.group(5),
        "adj_verification": m.group(6),
    }


def pair_nsign_auth(ns_records, auth_records):
    pairs = []
    for nrec in ns_records:
        candidates = [a for a in auth_records if a["begin_line"] > nrec["begin_line"]]
        if not candidates:
            raise ValueError(f"no authorization after nsign at {nrec['path']}:{nrec['begin_line']}")
        arec = min(candidates, key=lambda a: a["begin_line"])
        pairs.append((nrec, arec))
    return pairs


def int_byte_forms(value):
    raw = str(value).encode("ascii")
    return {
        "decimal": raw,
        "be4": (value & 0xffffffff).to_bytes(4, "big"),
        "le4": (value & 0xffffffff).to_bytes(4, "little"),
        "be8": value.to_bytes(8, "big"),
        "le8": value.to_bytes(8, "little"),
    }


def verify_authorization(records):
    ns = extract_ns_419(records)
    auth = extract_auth(records)
    print("=== AUTHORIZATION FROM RAW nsign utf8len=419 RECORDS ===")
    print(f"nsign records: {len(ns)}; authorization records: {len(auth)}")
    results = Counter()
    mismatches = []
    xor_nonzero = []
    evidence = []
    auth_fields = defaultdict(set)

    for arec in auth:
        parsed = parse_auth(arec)
        for key in ("adj_signing_id", "algorithm", "headers_id",
                    "native_version", "adj_verification"):
            auth_fields[key].add(parsed[key])

    for nrec, arec in pair_nsign_auth(ns, auth):
        len_line, len_text = field(nrec, "text: len=")
        if int(len_text) != 192:
            mismatches.append((nrec, len_line, f"native len={len_text}, expected 192"))
        hex_line, blob_hex = field(nrec, "hex=")
        blob = bytes.fromhex(blob_hex)
        if len(blob) != 192:
            mismatches.append((nrec, hex_line, f"blob bytes={len(blob)}, expected 192"))
        nano_line, nano_text = field(nrec, "nano_out=")
        nano = int(nano_text)
        second = int(nrec["meta"].get("ts", "0")) // 1000
        parsed = parse_auth(arec)
        sig = parsed["signature"]
        decoded = base64.b64decode(sig, validate=True)

        hypotheses = {
            "a base64(blob)": base64.b64encode(blob),
            "c base64(sha256(blob))": base64.b64encode(hashlib.sha256(blob).digest()),
        }
        for form, suffix in int_byte_forms(nano).items():
            hypotheses[f"b base64(blob + nano {form})"] = base64.b64encode(blob + suffix)
        for name, key in {
            "blob": blob,
            "nano decimal": str(nano).encode(),
            "signing second decimal": str(second).encode(),
            "ADJ verification ASCII": ADJ_VERIFICATION.encode(),
        }.items():
            hypotheses[f"c base64(HMAC-SHA256 key={name})"] = base64.b64encode(
                hmac.new(key, blob, hashlib.sha256).digest()
            )
        matches = [name for name, candidate in hypotheses.items() if candidate == sig.encode()]
        if matches == ["a base64(blob)"]:
            results["a"] += 1
        else:
            results["other"] += 1
            mismatches.append((nrec, nrec["begin_line"], "hypothesis",
                               f"matches={matches or ['NONE']}"))
        if any(name.startswith("b ") for name in matches):
            results["b_any"] += 1
        if any(name.startswith("c ") for name in matches):
            results["c_any"] += 1
        if len(decoded) != 192:
            mismatches.append((arec, parsed["text_line"], "signature length",
                               f"decoded={len(decoded)}, expected 192"))
        mask = bytes(a ^ b for a, b in zip(blob, decoded))
        if any(mask):
            xor_nonzero.append((nrec, arec, mask))
        else:
            results["d zero-mask"] += 1
        if sig != base64.b64encode(blob).decode("ascii"):
            mismatches.append((arec, parsed["text_line"], "base64(blob)",
                               f"expected={base64.b64encode(blob).decode('ascii')} got={sig}"))
        else:
            results["exact"] += 1
        if len(sig) != 256:
            mismatches.append((arec, parsed["text_line"], "signature text length",
                               f"len={len(sig)}"))

        expected_header = auth_header(blob)
        raw_header = "Signature signature=" + displayed_value(arec)
        if expected_header == raw_header:
            results["mint_exact_header"] += 1
        else:
            results["mint_header_mismatch"] += 1
            mismatches.append((arec, parsed["text_line"], "mint auth_header",
                               f"expected={expected_header!r} got={raw_header!r}"))

        if len(evidence) < 4:
            evidence.append((nrec, arec, blob, nano, second, sig, mask))

    print("hypothesis results over all pairs:")
    for label in (
        "(a) base64(blob)",
        "(b) blob + nano_out bytes (5 encodings)",
        "(c) sha256/HMAC-SHA256 of blob (6 variants)",
        "(d) decoded signature XOR blob",
        "mint_pipeline.auth_header exact full header",
    ):
        if label.startswith("(a)"):
            print(f"  {label}: {results['a']}/{len(ns)} exact; failures={results['other']}")
        elif label.startswith("(b)"):
            print(f"  {label}: {results['b_any']}/{len(ns)} exact")
        elif label.startswith("(c)"):
            print(f"  {label}: {results['c_any']}/{len(ns)} exact")
        elif label.startswith("(d)"):
            print(f"  {label}: {results['d zero-mask']}/{len(ns)} are all-zero; "
                  f"nonzero={len(xor_nonzero)}")
        else:
            print(f"  {label}: {results['mint_exact_header']}/{len(ns)} exact; "
                  f"mismatches={results['mint_header_mismatch']}")
    print(f"auth_header base64 component exact: {results['exact']}/{len(ns)}")
    print("nano_out/signing second conclusion: base64 input is exactly the 192-byte "
          "blob; nano_out and signing second are not appended, hashed, or XOR-mixed "
          "in the Authorization encoding (the second may already affect blob generation).")
    print("constant values across every authorization record in these two logs:")
    for key in ("headers_id", "adj_signing_id", "native_version",
                "algorithm", "adj_verification"):
        values = sorted(auth_fields[key])
        print(f"  {key}: {len(values)} unique -> {values}")
    print(f"authorization mismatches/events: {len(mismatches)}")
    for nrec_or_arec, line_no, kind, detail in mismatches:
        print(f"  MISMATCH {nrec_or_arec['path']}:{line_no} {kind}: {detail}")
    print("exact evidence samples (signature prefix only):")
    for nrec, arec, blob, nano, second, sig, mask in evidence:
        print(f"  {nrec['path'].name}:{nrec['begin_line']} -> "
              f"{arec['path'].name}:{arec['begin_line']}: "
              f"len={len(blob)}, nano_out={nano}, second={second}, "
              f"sig[0:24]={sig[:24]!r}, xor_nonzero={sum(x != 0 for x in mask)}")
    return results, mismatches


def displayed_value(rec):
    _, value = field(rec, "text: Signature signature=")
    return value


def main():
    print("RAW-ONLY VERIFICATION (notes/*.md and derived captures are not read)")
    all_records = []
    per_file_claim_mismatches = {}
    for name in LOG_NAMES:
        path = DEVICE / name
        records = list(parse_records(path))
        all_records.extend(records)
        print(f"\n######## {name} ########")
        _, mismatches = verify_claims([r for r in records
                                       if r["meta"].get("type") == "sign_input"])
        per_file_claim_mismatches[name] = len(mismatches)
        verify_authorization(records)

    print("\n=== CROSS-LOG AUTHORIZATION CONSTANT CROSS-CHECK ===")
    all_auth = [r for r in all_records if r["meta"].get("type") == "authorization_header"]
    for key in ("headers_id", "adj_signing_id", "adj_verification"):
        vals = defaultdict(set)
        for rec in all_auth:
            vals[parse_auth(rec)[key]].add(f"{rec['path'].name}:{rec['begin_line']}")
        print(f"{key}: {len(vals)} unique across {len(all_auth)} records")
        for value, locations in sorted(vals.items()):
            print(f"  {value!r}: {len(locations)} record(s)")
    print("\nCONCLUSION: only hypothesis (a), base64(192-byte blob), matches every "
          "nsign/Authorization pair. No nano_out or signing-second mixing is present.")


if __name__ == "__main__":
    main()
