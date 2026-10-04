"""_sub_event_law_prove.py — stage 3: derive and PROVE the Android adj9
/event claims law.

Method per signing:
  1. blob -> whiten_inverse -> record; verify layout constants.
  2. S = record[20:24] (BE), head16 = record[3:19], d9 = record[25:45],
     block = record[46:78].
  3. Candidate claims strings from the signing's own map, built with the
     signer's concatenation format (values in key order).
  4. sha256_iv2(d9 || 00 08 || head16 || LE32(S) || SHA0 || 01 00*16 ||
     claims) == block   ->  claims byte-exact.
  5. second: make_header(t) == blob[:16], t scanned +-120 s around nsign_ts.
  6. Full mint: build_record + whiten_forward + predict_digest == blob.

Candidate event laws (all: sorted profile, PINNED adj_signing_id, sorted
tail, BLOCK2 — varying membership of the event-specific keys):
  EVENT keys seen in maps: event_count, event_token, partner_params, seq
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_signer as sg                                            # noqa: E402
from _sub_unseal_core import whiten_inverse, record_constant_checks  # noqa: E402

SHA0 = hashlib.sha256(b"").digest()
SIG_JSON = os.path.join(HERE, "_sub_event_signings.json")

# event-specific keys observed in event signing maps (beyond the signer's
# PROFILE / SESSION_TAIL / BLOCK2 vocabularies)
EVENT_KEYS = ["event_count", "event_token", "partner_params", "seq"]


def unseal(blob):
    rec = whiten_inverse(blob[16:160], blob[:16])
    return rec, record_constant_checks(rec)


def block_hash(S, head16, d9, claims):
    msg = (bytes(d9) + b"\x00\x08" + bytes(head16)
           + struct.pack("<I", S & 0xFFFFFFFF) + SHA0 + b"\x01" + b"\x00" * 16
           + bytes(claims))
    return sg.sha256_iv2(msg)


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


def mint(second, S, head16, claims, d9):
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


def build_event_claims(mp, extra_profile, pinned_pos="after_profile",
                       extra_tail=()):
    """Candidate event law: presence-filtered, sorted profile (+ extras),
    pinned adj_signing_id, sorted tail (+ extras), BLOCK2.  Same value
    concatenation as sg.build_claims."""
    profile = list(sg.PROFILE) + list(extra_profile)
    tail = list(sg.SESSION_TAIL) + list(extra_tail)
    keys = [k for k in sorted(profile) if mp.get(k)]
    if pinned_pos == "after_profile":
        keys.append(sg.PINNED)
    elif pinned_pos == "alphabetical":
        pass  # handled by inserting into sorted profile below
    keys += [k for k in sorted(tail) if mp.get(k)]
    keys += [k for k in sg.BLOCK2 if mp.get(k)]
    if pinned_pos == "alphabetical":
        # re-sort everything except block2 with pinned inside
        base = [k for k in keys if k not in sg.BLOCK2]
        base = sorted(set(base + [sg.PINNED]))
        keys = base + [k for k in sg.BLOCK2 if mp.get(k)]
    parts = []
    for k in keys:
        v = sg.ADJ_SIGNING_ID if k == sg.PINNED else mp.get(k)
        if not v:
            return None, keys
        parts.append(v)
    return "".join(parts).encode("latin1"), keys


def main():
    with open(SIG_JSON, "r", encoding="utf-8") as f:
        signings = dedup(json.load(f))

    known = [s for s in signings
             if (s["map"] or {}).get("activity_kind")
             in ("session", "click", "attribution")]
    events = [s for s in signings
              if (s["map"] or {}).get("activity_kind") == "event"]

    # ---- sanity: full mint on known kinds with exact head16 from record
    ok = 0
    for s in known:
        blob = bytes.fromhex(s["blob_hex"])
        rec, checks = unseal(blob)
        if not all(checks.values()):
            continue
        sec = recover_second(blob, s["nsign_ts"])
        if sec is None:
            continue
        claims = sg.build_claims(s["map"], s["map"]["activity_kind"])
        if mint(sec, int.from_bytes(rec[20:24], "big"), rec[3:19], claims,
                rec[25:45]) == blob:
            ok += 1
    print("known-kind full mint (exact head16): %d/%d" % (ok, len(known)))

    # ---- arg3 cross-check: arg3_hex == sha256(claims)?
    arg3_ok = 0
    arg3_n = 0
    for s in known:
        if not s.get("arg3"):
            continue
        blob = bytes.fromhex(s["blob_hex"])
        rec, checks = unseal(blob)
        claims = sg.build_claims(s["map"], s["map"]["activity_kind"])
        arg3_n += 1
        if hashlib.sha256(claims).hexdigest() == s["arg3"]:
            arg3_ok += 1
    print("arg3 == sha256(claims) on known kinds: %d/%d" % (arg3_ok, arg3_n))

    # ---- enumerate extra keys present across all event maps
    extras = set()
    for s in events:
        mp = s["map"]
        for k in mp:
            if k not in sg.PROFILE and k not in sg.SESSION_TAIL \
                    and k not in sg.BLOCK2 and k != sg.PINNED:
                extras.add(k)
    print("event-map keys beyond known vocabulary:", sorted(extras))

    # ---- candidate laws: which extras join the profile (sorted in), and
    # where the pinned id sits.  Remaining extras (if any) go to tail.
    results = []
    for s in events:
        blob = bytes.fromhex(s["blob_hex"])
        rec, checks = unseal(blob)
        assert all(checks.values()), "record constants failed"
        S = int.from_bytes(rec[20:24], "big")
        head16, d9, block = rec[3:19], rec[25:45], rec[46:78]
        sec = recover_second(blob, s["nsign_ts"])
        mp = s["map"]
        hit = None
        tried = 0
        for r in range(len(EVENT_KEYS) + 1):
            for combo in itertools.combinations(EVENT_KEYS, r):
                tail_extra = tuple(k for k in EVENT_KEYS if k not in combo)
                for pos in ("after_profile", "alphabetical"):
                    tried += 1
                    claims, keys = build_event_claims(
                        mp, list(combo), pinned_pos=pos,
                        extra_tail=tail_extra)
                    if claims is None:
                        continue
                    if block_hash(S, head16, d9, claims) == block:
                        hit = {"extra_profile": list(combo), "pinned": pos,
                               "keys": keys, "claims": claims}
                        break
                if hit:
                    break
            if hit:
                break
        res = {"nsign_ts": s["nsign_ts"], "second": sec,
               "S": S, "d9": d9.hex(), "tried": tried,
               "event_token": mp.get("event_token"),
               "map_size": len(mp)}
        if hit:
            res.update({
                "law_extra_profile": hit["extra_profile"],
                "law_pinned": hit["pinned"],
                "law_keys": hit["keys"],
                "claims_len": len(hit["claims"]),
                "claims_sha256": hashlib.sha256(hit["claims"]).hexdigest(),
                "block_ok": True,
            })
            if sec is not None:
                res["full_mint"] = (mint(sec, S, head16, hit["claims"], d9)
                                    == blob)
        else:
            res.update({"block_ok": False, "full_mint": False})
        results.append(res)

    n_ok = sum(1 for r in results if r["block_ok"])
    n_mint = sum(1 for r in results if r.get("full_mint"))
    print("\nevent signings: %d  block_ok: %d  full_mint: %d"
          % (len(results), n_ok, n_mint))
    laws = set()
    for r in results:
        if r["block_ok"]:
            laws.add((tuple(r["law_extra_profile"]), r["law_pinned"]))
    print("winning laws:", laws)
    for r in results:
        print("  ts=%s kind_evt token=%-8s S=%-10u sec=%s claims_len=%s "
              "mint=%s extra=%s pinned=%s"
              % (r["nsign_ts"], r["event_token"], r["S"], r["second"],
                 r.get("claims_len"), r.get("full_mint"),
                 r.get("law_extra_profile"), r.get("law_pinned")))

    with open(os.path.join(HERE, "_sub_event_stage3.json"), "w") as f:
        json.dump(results, f, indent=1, default=str)


if __name__ == "__main__":
    main()
