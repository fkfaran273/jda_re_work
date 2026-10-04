"""Offline analysis of the three winning adj9 signatures in penti_android_test.saz.

Reads only the local SAZ and existing small JSON evidence. Writes saz_blobs.json
and prints a compact structural summary. No network or device access.
"""
from __future__ import annotations

import base64
import datetime as dt
import itertools
import json
import re
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile
from urllib.parse import parse_qsl, urlsplit

HERE = Path(__file__).resolve().parent
SAZ = Path(r"C:\Users\Apps\Downloads\penti_android_test.saz")
OUT = HERE / "saz_blobs.json"
sys.path.insert(0, str(HERE))

from desc10_law import build_desc10, desc10_keys
from header_gen import make_header
from mint_pipeline import INTERNAL_CLAIMS

CERT_SHA1 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
ADID = "2fedfd3dfcc48e92aae70f3fd2e1608a"
KIND_BY_PATH = {
    "/session": "session",
    "/sdk_click": "click",
    "/attribution": "attribution",
}
SIGNING_OFFSET_BY_PATH = {
    "/session": 1,
    "/sdk_click": 2,
    # Byte-level header inversion says floor(created_at), not +4:
    # make_header(1789388591) == 07184f3a... exactly.
    "/attribution": 0,
}


def iso_epoch(raw: str) -> int:
    """Adjust's Z+0530 spelling: local wall clock in a Z-prefixed value."""
    m = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{3})Z([+-])(\d{2})(\d{2})",
        raw,
    )
    if not m:
        raise ValueError(raw)
    local = dt.datetime.fromisoformat(m.group(1)).replace(
        microsecond=int(m.group(2)) * 1000
    )
    delta = dt.timedelta(hours=int(m.group(4)), minutes=int(m.group(5)))
    if m.group(3) == "-":
        delta = -delta
    return int((local.replace(tzinfo=dt.timezone.utc) - delta).timestamp())


def parse_units(z: ZipFile):
    units = []
    for sess in (1, 2, 3):
        request = z.read(f"raw/{sess}_c.txt").decode("utf-8", "replace")
        response = z.read(f"raw/{sess}_s.txt").decode("utf-8", "replace")
        head, _, body = request.partition("\r\n\r\n")
        request_line = head.splitlines()[0]
        method, url, _ = request_line.split(" ", 2)
        auth = re.search(
            r'Authorization: Signature signature="([A-Za-z0-9+/=]+)",'
            r'adj_signing_id="([^"]+)",algorithm="([^"]+)",headers_id="([^"]+)",'
            r'native_version="([^"]+)",adj_verification="([^"]+)"',
            head,
        )
        if not auth:
            raise RuntimeError(f"session {sess}: Authorization not found")
        sig_b64, signing_id, algorithm, headers_id, native_version, adjv = auth.groups()
        blob = base64.b64decode(sig_b64, validate=True)
        if len(blob) != 192:
            raise RuntimeError(f"session {sess}: {len(blob)} bytes")

        split = urlsplit(url)
        path = split.path
        kind = KIND_BY_PATH[path]
        params = {}
        for text in (body, split.query):
            for key, value in parse_qsl(text, keep_blank_values=True):
                params[key] = value

        claims = {}
        for key in desc10_keys(kind, params):
            if key == "activity_kind":
                claims[key] = kind
            elif key in INTERNAL_CLAIMS:
                claims[key] = INTERNAL_CLAIMS[key]
            else:
                claims[key] = str(params[key])
        claim_raw = build_desc10(claims, kind).encode("latin1")
        claim_padded = claim_raw + b"\0" * (-len(claim_raw) % 4)

        created_sec = iso_epoch(params["created_at"])
        sent_sec = iso_epoch(params["sent_at"])
        signing_second = created_sec + SIGNING_OFFSET_BY_PATH[path]
        expected_header = make_header(signing_second)
        if expected_header != blob[:16]:
            raise AssertionError(f"session {sess}: header mismatch")

        status = response.splitlines()[0]
        response_json = None
        response_text = response.partition("\r\n\r\n")[2]
        try:
            response_json = json.loads(response_text)
        except json.JSONDecodeError:
            pass

        units.append(
            {
                "session": sess,
                "method": method,
                "url": url,
                "path": path,
                "status": status,
                "activity_kind": kind,
                "params": params,
                "response_json": response_json,
                "authorization": {
                    "signature_base64": sig_b64,
                    "adj_signing_id": signing_id,
                    "algorithm": algorithm,
                    "headers_id": headers_id,
                    "native_version": native_version,
                    "adj_verification": adjv,
                },
                "signing_second": signing_second,
                "signing_second_basis": "floor(created_at)+%d; verified by header_gen.make_header" % SIGNING_OFFSET_BY_PATH[path],
                "created_at": params["created_at"],
                "sent_at": params["sent_at"],
                "created_at_epoch": created_sec,
                "sent_at_epoch": sent_sec,
                "blob_base64": sig_b64,
                "blob_hex": blob.hex(),
                "header_hex": blob[:16].hex(),
                "body_hex": blob[16:].hex(),
                "body_words_be": ["%08x" % x for x in struct.unpack(">44I", blob[16:])],
                "claim_law_hex": claim_padded.hex(),
                "claim_unpadded_length": len(claim_raw),
                "claim_padded_length": len(claim_padded),
                "claim_sha256": __import__("hashlib").sha256(claim_raw).hexdigest(),
                "header_law_match": True,
            }
        )
    return units


def pair_stats(units):
    out = []
    for left, right in itertools.combinations(units, 2):
        a = bytes.fromhex(left["body_hex"])
        b = bytes.fromhex(right["body_hex"])
        wa = struct.unpack(">44I", a)
        wb = struct.unpack(">44I", b)
        out.append(
            {
                "pair": [left["session"], right["session"]],
                "bytes_differing": sum(x != y for x, y in zip(a, b)),
                "words_equal": [i for i, (x, y) in enumerate(zip(wa, wb)) if x == y],
                "words_differing": sum(x != y for x, y in zip(wa, wb)),
            }
        )
    return out


def direct_match_analysis(units, corpus_h):
    body_words = [struct.unpack(">44I", bytes.fromhex(u["body_hex"])) for u in units]
    second_words = []
    adid_words = struct.unpack(">4I", bytes.fromhex(ADID))
    cert_words = struct.unpack(">5I", CERT_SHA1)
    claim_windows = []
    for u in units:
        raw = bytes.fromhex(u["claim_law_hex"])
        claim_windows.append({raw[i:i+4] for i in range(max(0, len(raw) - 3))})

    needle_results = []
    for i, u in enumerate(units):
        sec = u["signing_second"]
        needles = {
            "second_be": [struct.pack(">I", sec)],
            "second_le": [struct.pack("<I", sec)],
            "adid": [bytes.fromhex(ADID), ADID.encode()],
            "cert_sha1": [CERT_SHA1, CERT_SHA1.hex().encode()],
            "claims": sorted(claim_windows[i]),
            "corpus_h_dwords": [
                int(h[j:j+8], 16).to_bytes(4, "big")
                for h in corpus_h
                for j in range(0, 64, 8)
            ],
        }
        found = {}
        for name, values in needles.items():
            hits = []
            for value in values:
                start = 0
                while True:
                    at = u["body_hex"].find(value.hex())
                    if at < 0:
                        break
                    hits.append({"byte_hex_offset": at, "value_hex": value.hex()})
                    start = at + 1
            if hits:
                found[name] = hits
        needle_results.append({"session": u["session"], "direct_matches": found})

    positions = list(range(44))
    constant_positions = [p for p in positions if len({w[p] for w in body_words}) == 1]
    repeated = []
    for u, words in zip(units, body_words):
        by_value = {}
        for p, word in enumerate(words):
            by_value.setdefault("%08x" % word, []).append(p)
        repeated.append(
            {
                "session": u["session"],
                "repeated_word_values": {k: v for k, v in by_value.items() if len(v) > 1},
            }
        )
    return {
        "constant_word_positions_across_three": constant_positions,
        "all_44_positions_distinct_across_three": len({p for p in range(44) if len({w[p] for w in body_words}) == 3}) == 44,
        "pairwise": pair_stats(units),
        "within_body_repeats": repeated,
        "direct_needle_matches": needle_results,
        "pairwise_body_xor_zero_dwords": {
            f"{a['session']}^{b['session']}": [
                i for i, (x, y) in enumerate(zip(struct.unpack(">44I", bytes.fromhex(a["body_hex"])), struct.unpack(">44I", bytes.fromhex(b["body_hex"])))) if x == y
            ]
            for a, b in itertools.combinations(units, 2)
        },
        "known_reference_words": {
            "adid_be": ["%08x" % x for x in adid_words],
            "cert_sha1_be": ["%08x" % x for x in cert_words],
        },
    }


def main():
    with ZipFile(SAZ) as z:
        units = parse_units(z)
    pair_path = HERE / "pair_h3.json"
    corpus_h = []
    if pair_path.exists():
        corpus_h = [row["H"] for row in json.loads(pair_path.read_text(encoding="utf-8")) if row.get("H")]
    analysis = direct_match_analysis(units, corpus_h)
    doc = {
        "source_saz": str(SAZ),
        "offline_only": True,
        "capture_summary": {
            "adid": ADID,
            "winning_attribution_tracker_token": "24pxw9rl",
            "winning_attribution_network": "VKM Digital Yeni",
            "cert_sha1": CERT_SHA1.hex(),
        },
        "units": units,
        "analysis": analysis,
        "hmac_evidence": {
            "pair_h3_rows_checked": len(corpus_h),
            "result": "No pair_h3 HMAC, any of its 4-byte dwords, or a full 32-byte HMAC occurs as a direct substring in any SAZ body.",
            "important_negative_control": "rev/h_in_trace.log shows golden H 0/8 dwords in the VM trace, descriptor #4 8/8, and the blob 48/48.",
        },
        "forgeability_evidence": {
            "header": "Offline exact: make_header(signing_second), 3/3.",
            "claims": "Offline exact law: desc10_law, 360/388/248? bytes recorded per unit.",
            "merge": "fin_vm2.FinEx reproduces 48/48 words from its descriptor set; no H argument is passed.",
            "region": "F.region(V,pid,tid) is a fully lifted pure-Python function; the residual exact historical requirement is V=tv_sec^tv_usec and low16(pid), neither of which is present in this SAZ.",
        },
    }
    OUT.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print("wrote", OUT)
    for u in units:
        print(
            f"s{u['session']} {u['path']:12} sec={u['signing_second']} "
            f"claims={u['claim_unpadded_length']}/{u['claim_padded_length']} "
            f"header={u['header_hex']} body={u['body_hex'][:32]}…"
        )
    print("constant body word positions:", analysis["constant_word_positions_across_three"])
    print("all 44 positions distinct:", analysis["all_44_positions_distinct_across_three"])
    print("pairwise differing bytes:", [(x["pair"], x["bytes_differing"]) for x in analysis["pairwise"]])
    print("direct matches:", analysis["direct_needle_matches"])


if __name__ == "__main__":
    main()
