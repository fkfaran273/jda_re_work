"""_sub_event_law_analyze.py — stage 2: calibrate the mapget-order rule on
known-kind signings, then derive + prove the event claims law.

Proof chain per signing:
  blob -> whiten_inverse -> record (magic checks) -> S=rec[20:24], head16,
  d9=rec[25:45], block=rec[46:78]
  candidate claims (from mapget order) ->
  sha256_iv2(d9 || 00 08 || head16 || LE32(S) || SHA0 || 01 00*16 || claims)
  == block            -> claims string byte-exact
  make_header(second) == blob[:16]  (second scanned around nsign_ts/1000)
  sign_pure(second, S, claims, d9, head) == blob  -> FULL MINT PROOF
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_signer as sg                                   # noqa: E402
from _sub_unseal_core import whiten_inverse, record_constant_checks  # noqa: E402

SHA0 = hashlib.sha256(b"").digest()
SIG_JSON = os.path.join(HERE, "_sub_event_signings.json")


def unseal(blob):
    rec = whiten_inverse(blob[16:160], blob[:16])
    checks = record_constant_checks(rec)
    return rec, checks


def block_ok(S, head16, d9, claims, block):
    msg = (bytes(d9) + b"\x00\x08" + bytes(head16)
           + struct.pack("<I", S & 0xFFFFFFFF) + SHA0 + b"\x01" + b"\x00" * 16
           + bytes(claims))
    return sg.sha256_iv2(msg) == block


def recover_second(blob, ts_ms, span=120):
    target = blob[:16]
    base = ts_ms // 1000 if ts_ms else None
    if base is None:
        return None
    for d in range(span + 1):
        for t in ((base - d, base + d) if d else (base,)):
            if sg.make_header(t) == target:
                return t
    return None


def dedup(signings):
    seen, out = set(), []
    for s in signings:
        b = s.get("blob_hex")
        if not b or b in seen:
            continue
        seen.add(b)
        out.append(s)
    return out


def mapget_groups(s):
    """Group the window mapgets by map object id, preserving order."""
    groups = {}
    for ts, this_id, key, val in s["mapgets"]:
        groups.setdefault(this_id, []).append((ts, key, val))
    return groups


def dedupe_keys(seq):
    """First-occurrence-unique key list."""
    seen, out = set(), []
    for k in seq:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def claims_from_order(order, mp):
    parts = []
    used = {}
    for k in order:
        v = mp.get(k)
        if v is None or v == "":
            continue
        parts.append(v)
        used[k] = v
    return "".join(parts).encode("latin1"), used


def analyze():
    with open(SIG_JSON, "r", encoding="utf-8") as f:
        signings = json.load(f)
    signings = dedup(signings)
    print("deduped signings:", len(signings))

    by_kind = {}
    for s in signings:
        kind = (s.get("map") or {}).get("activity_kind", "?")
        by_kind.setdefault(kind, []).append(s)
    print({k: len(v) for k, v in by_kind.items()})

    # ---- step 1: unseal every signing, verify record + digest + block vs
    # known law for known kinds
    results = []
    for s in signings:
        blob = bytes.fromhex(s["blob_hex"])
        rec, checks = unseal(blob)
        info = {
            "file": s["file"], "kind": (s.get("map") or {}).get("activity_kind"),
            "const_ok": all(checks.values()),
            "digest_ok": sg.predict_digest(blob[16:160]) == blob[160:192],
            "S": int.from_bytes(rec[20:24], "big"),
            "d9": rec[25:45].hex(),
            "head16": rec[3:19].hex(),
            "nsign_ts": s["nsign_ts"],
        }
        if info["const_ok"]:
            mp = s["map"]
            second = recover_second(blob, s["nsign_ts"])
            info["second"] = second
            if info["kind"] in ("session", "click", "attribution"):
                claims = sg.build_claims(mp, info["kind"])
                info["known_law_block_ok"] = block_ok(
                    info["S"], rec[3:19], rec[25:45], claims, rec[46:78])
                info["known_law_full_mint"] = (
                    second is not None and
                    sg.sign_pure(second, info["S"], mp, d9_hex=info["d9"],
                                 kind=info["kind"]) == blob)
                info["claims_len"] = len(claims)
            if s.get("arg3"):
                info["arg3_is_sha_claims_unknown"] = None
        results.append(info)

    known = [r for r in results if r["kind"] in ("session", "click",
                                                 "attribution")]
    print("known-kind signings: %d  const_ok=%d  digest_ok=%d  "
          "law_block_ok=%s  full_mint=%s"
          % (len(known), sum(r["const_ok"] for r in known),
             sum(r["digest_ok"] for r in known),
             sum(r.get("known_law_block_ok", False) for r in known),
             sum(r.get("known_law_full_mint", False) for r in known)))
    bad = [r for r in known if not (r["const_ok"] and r["digest_ok"]
                                    and r.get("known_law_block_ok"))]
    for r in bad[:5]:
        print("  BAD:", r["file"], r["kind"], r["const_ok"], r["digest_ok"],
              r.get("known_law_block_ok"), "second=", r.get("second"))
    evts = [r for r in results if r["kind"] == "event"]
    print("event signings: %d  const_ok=%d  digest_ok=%d  second_found=%d"
          % (len(evts), sum(r["const_ok"] for r in evts),
             sum(r["digest_ok"] for r in evts),
             sum(1 for r in evts if r.get("second") is not None)))

    with open(os.path.join(HERE, "_sub_event_stage1.json"), "w") as f:
        json.dump(results, f, indent=1)
    return signings, results


if __name__ == "__main__":
    analyze()
