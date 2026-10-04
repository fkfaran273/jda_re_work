"""blob_diff_final.py — the consolidated, reproducible result set for blob_diff.md.

Runs, in order:
  1. genuine blob decode (record fields, S, region, head prefix)
  2. mint with the app's OWN claims + second + the S-derived region  -> 192-B diff
  3. mint with app_session_params_real.json (the 2026-09-25 identity) -> 192-B diff
  4. the head-phase table (which selector prefix reproduces the genuine head)
  5. the L1/L2/L3 law table over all 6 genuine blobs
  6. the [46:78) / tail2 provenance (input vs FinEx output)
"""
import base64
import hashlib
import hmac
import itertools
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
from header_gen import make_header
from blob_diff_run import (_blocks, _text, find_genuine, parse_map,
                           find_head_prefix, region_from_S, field_diff)

SECOND = 1790517288
OUT = {}


def words(b):
    return [b[i:i + 4] for i in range(0, len(b), 4)]


def blob_diff(a, b):
    aw, bw = words(a), words(b)
    return {"header_match": a[:16] == b[:16],
            "words_differing": [i for i in range(48) if aw[i] != bw[i]],
            "header": a[:16].hex(), "other_header": b[:16].hex()}


def main():
    gen = base64.b64decode(open(os.path.join(HERE, "transport_blob.txt"))
                           .read().strip())
    gd = W.decode_blob(gen)
    grec = gd["record"]
    S = gd["F_seed"]
    info = find_genuine(base64.b64encode(gen).decode())
    si = _text(info["sign_input"])
    app_map = parse_map(re.search(r"map_toString=\{(.*?)\}\n", si, re.S).group(1))
    pre = find_head_prefix(S, grec[3:19])

    OUT["second"] = SECOND
    OUT["auth_record_ts"] = info["auth_ts"]
    OUT["nsign_record_ts"] = info.get("nsign_ts")
    OUT["genuine_blob_hex"] = gen.hex()
    OUT["genuine_record_hex"] = grec.hex()
    OUT["genuine_S"] = "%08x" % S
    OUT["genuine_d2w"] = "%08x" % gd["d2w"]
    OUT["genuine_head"] = grec[3:19].hex()
    OUT["genuine_head_prefix"] = [hex(x) for x in pre]
    OUT["genuine_block32"] = gd["block"].hex()
    OUT["genuine_tail2"] = gd["tail2"].hex()
    OUT["consts_ok"] = gd["consts_ok"]

    d0, d2, d4 = region_from_S(S, pre)
    d0b = b"".join(x.to_bytes(4, "big") for x in d0)
    d2b = d2.to_bytes(4, "big")
    d4b = b"".join(x.to_bytes(4, "big") for x in d4)

    # ---- 2. the app's own claims -------------------------------------------
    claims = MP.claims_from_wire(app_map, "session")
    d10 = desc10_law.build_desc10(claims, "session")
    descs, meta = MP.build_descriptors(claims, "session", d0b, d2b, d4b)
    ours, minfo = MP.finex_mint(descs, SECOND)
    od = W.decode_blob(ours)
    OUT["mint_ownclaims"] = blob_diff(gen, ours)
    OUT["mint_ownclaims"]["blob_hex"] = ours.hex()
    OUT["mint_ownclaims"]["record_hex"] = od["record"].hex()
    OUT["mint_ownclaims"]["field_diff"] = field_diff(grec, od["record"])
    OUT["mint_ownclaims"]["fin_ex"] = {k: minfo[k] for k in
                                       ("status", "steps", "nrand", "stream")}
    OUT["desc10_unpadded"] = meta["desc10_unpadded"]
    OUT["desc10"] = d10
    OUT["desc10_keys"] = desc10_law.desc10_keys("session", claims)

    # ---- 3. app_session_params_real.json ------------------------------------
    real = json.load(open(os.path.join(HERE, "app_session_params_real.json")))
    rp = MP.claims_from_wire(real, "session")
    rdescs, rmeta = MP.build_descriptors(rp, "session", d0b, d2b, d4b)
    rours, _ = MP.finex_mint(rdescs, SECOND)
    rod = W.decode_blob(rours)
    OUT["mint_realjson"] = blob_diff(gen, rours)
    OUT["mint_realjson"]["blob_hex"] = rours.hex()
    OUT["mint_realjson"]["record_hex"] = rod["record"].hex()
    OUT["mint_realjson"]["field_diff"] = field_diff(grec, rod["record"])
    OUT["mint_realjson"]["desc10_unpadded"] = rmeta["desc10_unpadded"]
    OUT["mint_realjson"]["param_mismatch_vs_capture"] = {
        k: {"app_session_params_real": real.get(k), "captured_sign_input": app_map.get(k)}
        for k in real if real.get(k) != app_map.get(k)}

    # ---- 4. head-phase table -----------------------------------------------
    OUT["head_table"] = []
    for nm, h in (("F.HEAD_FIRST", Fmod.HEAD_FIRST),
                  ("F.HEAD_RESIGN", Fmod.HEAD_RESIGN),
                  ("MP.DEVICE_SELECTORS (mint_pipeline default)",
                   MP.DEVICE_SELECTORS),
                  ("recovered genuine prefix (0x2b,)", pre)):
        dw = Fmod._d0_words(d4, head=h)
        dwb = b"".join(x.to_bytes(4, "big") for x in dw)
        hw = W.head_words(dw)
        OUT["head_table"].append({
            "name": nm, "selectors": [hex(x) for x in h], "head": hw.hex(),
            "matches": hw == grec[3:19],
            "laws": MP.region_laws(dwb, d4b)})

    # ---- 5. all six genuine blobs ------------------------------------------
    raw = open(os.path.join(HERE, "transport_capture_log.txt"),
               encoding="utf-8", errors="replace").read()
    rows = []
    for m in re.finditer(r"type=authorization_header utf8len=407 ts=(\d+)\n"
                         r'text: Signature signature="([A-Za-z0-9+/=]+)"', raw):
        ts = int(m.group(1))
        b = base64.b64decode(m.group(2))
        sec = next((s for s in range(ts // 1000 - 40, ts // 1000 + 40)
                    if make_header(s) == b[:16]), None)
        d = W.decode_blob(b)
        p = find_head_prefix(d["F_seed"], d["head"])
        d4i = Fmod._d4_words(d["F_seed"])
        d4ib = b"".join(x.to_bytes(4, "big") for x in d4i)
        laws = {}
        for nm, h in (("genuine", p), ("HEAD_FIRST", Fmod.HEAD_FIRST),
                      ("HEAD_RESIGN", Fmod.HEAD_RESIGN),
                      ("DEVICE_SELECTORS", MP.DEVICE_SELECTORS)):
            dw = b"".join(x.to_bytes(4, "big") for x in Fmod._d0_words(d4i, head=h))
            L = MP.region_laws(dw, d4ib)
            laws[nm] = {"L1": L["L1_tile_Rrep"], "L2": L["L2_d4_6_hi_eq_R"],
                        "L3": L["L3_X_eq_U3"],
                        "head_match": W.head_words(Fmod._d0_words(d4i, head=h))
                        == d["head"]}
        rows.append({"ts": ts, "second": sec, "S": "%08x" % d["F_seed"],
                     "d2w": "%08x" % d["d2w"], "tail2": d["tail2"].hex(),
                     "consts_ok": d["consts_ok"],
                     "head_prefix": [hex(x) for x in p], "laws": laws})
    OUT["all_six"] = rows

    # ---- 6. block32 / tail2 provenance -------------------------------------
    ref = gd["block"]
    pert = []
    by_build = {b: i for i, b in enumerate(MP.VA_ORDER)}
    for b in MP.VA_ORDER:
        L, _, data = descs[by_build[b]]
        if not data:
            pert.append({"build_idx": b, "len_dw": L, "note": "empty"})
            continue
        nb = bytearray(data)
        nb[0] ^= 0x01
        ds = list(descs)
        ds[by_build[b]] = (L, 0, bytes(nb))
        try:
            bb, _ = MP.finex_mint(ds, SECOND, max_steps=200_000_000)
        except RuntimeError:
            pert.append({"build_idx": b, "len_dw": L, "note": "no emission"})
            continue
        r2 = W.decode_blob(bb)["record"]
        pert.append({"build_idx": b, "len_dw": L,
                     "block32_changes": r2[46:78] != ref,
                     "tail2": r2[128:130].hex()})
    OUT["block32_perturbation"] = pert

    # law hunt (SHA/HMAC preimage) — the negative control
    parts = {"head": grec[3:19], "S": struct.pack(">I", S), "d4": d4b,
             "d0": d0b, "d2": d2b, "cert": grec[25:45], "sha0": grec[79:111],
             "record": grec, "claims": d10.encode("latin1"),
             "second": struct.pack(">I", SECOND), "empty": b"",
             "zeros14": b"\x00" * 14, "ones14": b"\x0e" * 14}
    names = list(parts)
    hits = []
    for n in (1, 2, 3):
        for combo in itertools.permutations(names, n):
            msg = b"".join(parts[c] for c in combo)
            h = hashlib.sha256(msg).digest()
            if h[:32] == ref or h[-32:] == ref:
                hits.append(("sha256", combo))
            if hashlib.sha1(msg).digest() * 2 == ref:
                hits.append(("sha1x2", combo))
            if hashlib.md5(msg).digest() * 2 == ref:
                hits.append(("md5x2", combo))
    for k in names:
        for m2 in names:
            if hmac.new(parts[k], parts[m2], hashlib.sha256).digest() == ref:
                hits.append(("hmac-sha256", (k, m2)))
    OUT["block32_preimage_hits"] = hits
    OUT["block32_preimage_search_space"] = (
        "sha256/sha1x2/md5x2 over all 1-3-part permutations of %d tokens "
        "(%d messages) + %d HMAC-SHA256 key/msg pairs"
        % (len(names), sum(len(names) ** i for i in (1, 2, 3)),
           len(names) ** 2))

    return OUT


if __name__ == "__main__":
    o = main()
    p = os.path.join(HERE, "blob_diff_data.json")
    json.dump(o, open(p, "w"), indent=1, ensure_ascii=False)
    print("header match          :", o["mint_ownclaims"]["header_match"])
    print("words differing       :",
          len(o["mint_ownclaims"]["words_differing"]), "/48")
    print("record fields differing:",
          [r["field"] for r in o["mint_ownclaims"]["field_diff"] if not r["equal"]])
    print("realjson words differing: %d/48" %
          len(o["mint_realjson"]["words_differing"]))
    print("realjson record fields differing:",
          [r["field"] for r in o["mint_realjson"]["field_diff"] if not r["equal"]])
    print("block32 preimage hits :", o["block32_preimage_hits"] or "NONE")
    print("wrote", p)
