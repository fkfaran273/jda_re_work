"""blob_diff_run2.py — the two remaining questions.

(A) The literal task variant: mint with app_session_params_real.json (the
    2026-09-25 identity) at the genuine second, against the genuine 192 B.
(B) The claims comparison: our desc10 law vs the app's own canonical record
    (key order + values) and vs the app's wire body.
(C) Is [46:78)/tail2 a free field, or an OUTPUT of the descriptor set?
    -> permute one descriptor at a time and watch the block move.
"""
import base64
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import F as Fmod
import whiten_decoder as W
import mint_pipeline as MP
import desc10_law
from blob_diff_run import (_blocks, _text, find_genuine, parse_map,
                           find_head_prefix, region_from_S, field_diff, FIELDS)

SECOND = 1790517288


def d_of(blob):
    return W.decode_blob(blob)


def show_field_diff(grec, orec, label):
    print("  -- %s --" % label)
    for r in field_diff(grec, orec):
        print("   %-16s %-10s %s" % (r["field"], r["range"],
                                     "SAME" if r["equal"] else "DIFF"))
        if not r["equal"]:
            print("       genuine: %s" % r["genuine"])
            print("       ours   : %s" % r["ours"])


def main():
    gen = base64.b64decode(open(os.path.join(HERE, "transport_blob.txt"))
                           .read().strip())
    gd = d_of(gen)
    grec = gd["record"]
    info = find_genuine(base64.b64encode(gen).decode())
    si = _text(info["sign_input"])
    app_map = parse_map(re.search(r"map_toString=\{(.*?)\}\n", si, re.S).group(1))
    S = gd["F_seed"]
    pre = find_head_prefix(S, grec[3:19])

    print("=" * 78)
    print("(A) LITERAL VARIANT: app_session_params_real.json at second %d" % SECOND)
    print("=" * 78)
    real = json.load(open(os.path.join(HERE, "app_session_params_real.json")))
    print("  app_session_params_real.json: %d keys, gps=%s uuid=%s created=%s"
          % (len(real), real["gps_adid"][:8], real["android_uuid"][:8],
             real["created_at"]))
    si_real = app_map
    for k in ("gps_adid", "android_uuid", "created_at", "sent_at", "updated_at",
              "installed_at", "store_name_from_system", "package_name",
              "initiating_package_name", "app_version", "language"):
        a, b = real.get(k), si_real.get(k)
        if a != b:
            print("    PARAM MISMATCH %-26s real=%-40s captured=%s"
                  % (k, a, b))

    rp = MP.claims_from_wire(real, "session")
    d0, d2, d4 = region_from_S(S, pre)
    d0b = b"".join(x.to_bytes(4, "big") for x in d0)
    d2b = d2.to_bytes(4, "big")
    d4b = b"".join(x.to_bytes(4, "big") for x in d4)
    descs, meta = MP.build_descriptors(rp, "session", d0b, d2b, d4b)
    ours, _ = MP.finex_mint(descs, SECOND)
    od = d_of(ours)
    gw = [gen[i:i + 4] for i in range(0, 192, 4)]
    ow = [ours[i:i + 4] for i in range(0, 192, 4)]
    diffw = [i for i in range(48) if gw[i] != ow[i]]
    print("  header match : %s" % (gen[:16] == ours[:16]))
    print("  words differing: %d/48 -> %s" % (len(diffw), diffw))
    print("  desc10 unpadded %d B (vs genuine-session 360 B)"
          % meta["desc10_unpadded"])
    show_field_diff(grec, od["record"], "record diff (real-params mint)")

    print()
    print("=" * 78)
    print("(B) CLAIMS: desc10 law vs the app's canonical record")
    print("=" * 78)
    cn = [(t2, ls) for (t, t2, ls) in _blocks(
        os.path.join(HERE, "transport_capture_log.txt"))
        if t == "canonical" and t2 <= info["auth_ts"] + 50]
    canon = None
    for t2, ls in sorted(cn, key=lambda x: -x[0]):
        t = _text(ls).strip()
        if t.startswith("{"):
            canon = t
            break
    app_can = parse_map(canon[1:-1])
    print("  app canonical : %d keys, %d chars" % (len(app_can), len(canon)))
    our_claims = MP.claims_from_wire(app_map, "session")
    d10 = desc10_law.build_desc10(our_claims, "session")
    print("  our desc10    : %d B over %d law keys"
          % (len(d10), len(desc10_law.desc10_keys('session', our_claims))))
    print("  law key order : %s" % ",".join(desc10_law.desc10_keys(
        'session', our_claims)))
    # value-level check: every canonical value must appear inside our desc10
    missing = [k for k, v in app_can.items() if v not in d10]
    print("  canonical values NOT found in our desc10: %s"
          % (missing or "none - all 48 values present"))
    # order check
    pos = [d10.find(app_can[k]) for k in app_can]
    inc = all(pos[i] < pos[i + 1] for i in range(len(pos) - 1))
    print("  canonical key order preserved in desc10: %s" % inc)
    if not inc:
        for i in range(len(pos) - 1):
            if pos[i] >= pos[i + 1]:
                print("     break after %s (pos %d) at %s (pos %d)"
                      % (list(app_can)[i], pos[i], list(app_can)[i + 1],
                         pos[i + 1]))
                break
    print("  desc10 head  : %s" % d10[:80])
    print("  desc10 tail  : %s" % d10[-60:])

    print()
    print("  -- wire body (transport/fp_session_body.txt) vs captured sign_input --")
    body = open(os.path.join(HERE, "transport", "fp_session_body.txt"),
                encoding="utf-8").read().strip()
    bp = {}
    for kv in body.split("&"):
        k, _, v = kv.partition("=")
        bp[re.sub(r"%([0-9A-Fa-f]{2})",
                  lambda m: chr(int(m.group(1), 16)), k)] = \
            re.sub(r"%([0-9A-Fa-f]{2})",
                   lambda m: chr(int(m.group(1), 16)), v)
    only_b = sorted(set(bp) - set(app_map))
    only_s = sorted(set(app_map) - set(bp))
    diff_v = {k: (bp[k], app_map[k]) for k in set(bp) & set(app_map)
              if bp[k] != app_map[k]}
    print("    wire keys %d, sign_input keys %d" % (len(bp), len(app_map)))
    print("    only on wire        : %s" % (only_b or "-"))
    print("    only in sign_input  : %s" % (only_s or "-"))
    print("    values differing    : %d" % len(diff_v))
    for k, (a, b) in sorted(diff_v.items()):
        print("      %-26s wire=%s  sign_input=%s" % (k, a, b))

    print()
    print("=" * 78)
    print("(C) is [46:78) an INPUT or an OUTPUT of the descriptor set?")
    print("=" * 78)
    base = desc10_law.build_desc10(our_claims, "session").encode("latin1")
    padded = base + b"\x00" * (-len(base) % 4)
    ref = gd["block"]
    trials = []
    # flip the first bit of ONE descriptor, by BUILD index (descs[] is VA order)
    by_build = {b: i for i, b in enumerate(MP.VA_ORDER)}
    print("  perturb 1 bit of ONE descriptor -> does [46:78) still match?")
    print("  (descs[] is in VA_ORDER %s; label = build_idx)" % MP.VA_ORDER)
    for b in MP.VA_ORDER:
        L, _, data = descs[by_build[b]]
        if not data:
            print("    desc#%-2d (len %3d): EMPTY, skipped" % (b, L))
            continue
        nb = bytearray(data)
        nb[0] ^= 0x01
        d2s = list(descs)
        d2s[by_build[b]] = (L, 0, bytes(nb))
        try:
            b2, _ = MP.finex_mint(d2s, SECOND, max_steps=200_000_000)
        except RuntimeError:
            print("    desc#%-2d (len %3d): VM emitted no stream" % (b, L))
            continue
        r2 = W.decode_blob(b2)["record"]
        same = r2[46:78] == ref
        trials.append((b, L, same, r2[128:130].hex()))
        print("    desc#%-2d (len %3d): block32 %-9s  tail2=%s"
              % (b, L, "UNCHANGED" if same else "changes", r2[128:130].hex()))
    return dict(grec=grec, real_ours=ours, real_rec=od["record"],
                d10=d10, canon=canon, diffw=diffw, trials=trials,
                app_map=app_map, bp=bp, diff_v=diff_v, only_b=only_b,
                only_s=only_s, S=S, pre=pre)


if __name__ == "__main__":
    r = main()
    json.dump({
        "second": SECOND,
        "real_params_mint_blob_hex": r["real_ours"].hex(),
        "real_params_mint_record_hex": r["real_rec"].hex(),
        "words_differing": r["diffw"],
        "desc10": r["d10"],
        "app_canonical": r["canon"],
        "canonical_missing_from_desc10": [k for k, v in r["app_map"].items()
                                          if v not in r["d10"]],
        "body_only_wire": r["only_b"],
        "body_only_sign_input": r["only_s"],
        "body_value_diffs": r["diff_v"],
        "perturb_trials": r["trials"],
    }, open(os.path.join(HERE, "blob_diff_data2.json"), "w"), indent=1,
        ensure_ascii=False)
    print("\nwrote blob_diff_data2.json")
