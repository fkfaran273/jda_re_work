"""_sub_event_law_calib.py — calibrate the mapget-order -> claims-order rule
on known-kind signings, then apply to event signings and prove by block hash
+ full mint."""
from __future__ import annotations

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
    return rec, record_constant_checks(rec)


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


def mint_from_record(second, S, head16, claims, d9):
    """Full 192-B mint using the exact head16 from the captured record."""
    record = sg.build_record(S, head16, claims, d9)
    header = sg.make_header(second)
    body = sg.whiten_forward(record, header)
    return header + body + sg.predict_digest(body)


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
    groups = {}
    for ts, this_id, key, val in s["mapgets"]:
        groups.setdefault(this_id, []).append((ts, key, val))
    return groups


def dedupe_keys(seq):
    seen, out = set(), []
    for k in seq:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def claims_from_order(order, mp):
    parts = []
    for k in order:
        v = mp.get(k)
        if v is None or v == "":
            continue
        parts.append(v)
    return "".join(parts).encode("latin1")


def show_groups(s, kind_label, max_groups=6):
    gs = mapget_groups(s)
    print("== %s  ts=%s  groups=%d" % (kind_label, s["nsign_ts"], len(gs)))
    for gid, seq in list(gs.items())[:max_groups]:
        ks = dedupe_keys(k for _t, k, _v in seq)
        print("  this=%s ngets=%3d uniq=%2d: %s"
              % (gid, len(seq), len(ks), ",".join(ks)))
    return gs


def main():
    with open(SIG_JSON, "r", encoding="utf-8") as f:
        signings = dedup(json.load(f))

    # pick the first session signing WITH mapgets and show its groups
    for s in signings:
        if (s["map"] or {}).get("activity_kind") == "session" and s["mapgets"]:
            blob = bytes.fromhex(s["blob_hex"])
            rec, checks = unseal(blob)
            assert all(checks.values())
            mp = s["map"]
            law = sg.desc10_keys(mp, "session")
            print("KNOWN session law order:\n  ", ",".join(law))
            show_groups(s, "session")
            break
    for s in signings:
        if (s["map"] or {}).get("activity_kind") == "event" and s["mapgets"]:
            show_groups(s, "event")
            break


if __name__ == "__main__":
    main()
