"""_sub_claims3_oracle_fixed.py — BLOCKING-fix for the batch BLOCK oracle.

The previous oracle (_sub_ios_claims2_oracle.oracle_batch) zero-fills all
rows to the batch's max length.  A row shorter than the max therefore has
extra all-zero blocks digested after its length field -> WRONG digest for
every non-longest row in a mixed-length batch.  Positive-control proof
(forged record whose block matches a short claim): the true hit is found
when batched alone and MISSED when batched with a longer claim.  This
corrupted every mixed-length batch in the prior ~67M-candidate searches.

Fix: group rows by identical padded length and batch per group.  Rows within
a group share T, so zero-fill never occurs.

API:
    oracle_batch_fixed(rec, claims_list) -> bool array  (iOS record frame)
    oracle_frames_fixed(rec, claims_list, d9, magic, tail_bytes)
Validation:
    selftest() -> (golds_ok, positive_controls_ok)
"""
import hashlib
import struct

import numpy as np

import adj9_signer as sg
import _sub_np_sha256 as npsha

SHA0 = hashlib.sha256(b"").digest()


def _ios_msg_head(rec, d9=None, magic=b"\x00\x08", tail_bytes=None):
    if d9 is None:
        d9 = b"\x00" * 20
    if tail_bytes is None:
        tail_bytes = bytes([0x02]) + rec["dev"]
    return (d9 + magic + rec["head16"] + struct.pack("<I", rec["S"]) + SHA0
            + tail_bytes)


def _batch_bool(msg_head, claims_list, target):
    pref = msg_head[:64]
    rest0 = msg_head[64:]
    L0 = len(msg_head)
    rows = []
    for c in claims_list:
        c = c.encode("latin1") if isinstance(c, str) else bytes(c)
        total = L0 + len(c)
        t = rest0 + c + b"\x80" + b"\x00" * ((55 - total) % 64) \
            + struct.pack(">Q", total * 8)
        rows.append(np.frombuffer(t, np.uint8))
    out = np.zeros(len(rows), dtype=bool)
    # group by identical row length (=> identical block count)
    by_len = {}
    for i, row in enumerate(rows):
        by_len.setdefault(len(row), []).append(i)
    for L, idxs in by_len.items():
        arr = np.zeros((len(idxs), L), dtype=np.uint8)
        for j, i in enumerate(idxs):
            arr[j] = rows[i]
        words = npsha.batch_digests(pref, arr)
        ok = (words == target).all(axis=1)
        for j, i in enumerate(idxs):
            out[i] = ok[j]
    return out


def oracle_batch_fixed(rec, claims_list):
    msg_head = _ios_msg_head(rec)
    target = np.frombuffer(rec["block"], ">u4").astype(np.uint32)
    return _batch_bool(msg_head, claims_list, target)


def oracle_frames_fixed(rec, claims_list, d9, magic, tail_bytes):
    msg_head = _ios_msg_head(rec, d9=d9, magic=magic, tail_bytes=tail_bytes)
    target = np.frombuffer(rec["block"], ">u4").astype(np.uint32)
    return _batch_bool(msg_head, claims_list, target)


def selftest():
    """1) Android golds through the generic frame (positive control).
    2) Forged-hit positive controls: short claim missed by the OLD oracle in
    a mixed batch must be found by the fixed one."""
    from _sub_unseal_core import whiten_inverse
    golds_ok = 0
    for g in sg.GOLD_VECTORS:
        blob = bytes.fromhex(g["blob_hex"])
        recb = whiten_inverse(blob[16:160], blob[:16])
        S = int.from_bytes(recb[20:24], "big")
        rec = {"head16": recb[3:19], "S": S, "block": recb[46:78],
               "dev": recb[114:130]}
        claims = sg.build_claims(g["map"], g["kind"], signing_id="1500000")
        if g["kind"] == "event":
            val = dict(g["map"])
            prof = [k for k in sg.PROFILE + ["event_count", "event_token",
                                             "partner_params"] if val.get(k)]
            tail = [k for k in sg.SESSION_TAIL + ["seq"] if val.get(k)]
            parts = [val[k] for k in sorted(prof)] + ["1500000"] \
                + [val[k] for k in sorted(tail)] \
                + [g["kind"] + val["client_sdk"] + "10" + "5.0.0"]
            claims = "".join(parts).encode("latin1")
        elif g["kind"] != "session":
            claims = sg.build_claims(g["map"], g["kind"],
                                     signing_id="1500000")
        arr = oracle_frames_fixed(rec, [claims],
                                  bytes.fromhex(g["d9_hex"]),
                                  b"\x00\x08", b"\x01" + b"\x00" * 16)
        golds_ok += int(arr[0])

    # forged-hit controls on the session record
    import _sub_claims3_search as S1
    corpus = S1.load_corpus()
    r = dict([x for x in corpus if x["file"] == "0144_c.txt"][0])

    def true_block(claims):
        msg = _ios_msg_head(r) + claims
        return sg.sha256_iv2(msg)

    c_long = S1.LAWS["sorted_split"](r, S1.base_opts(np="body",
                                                     auth="nosig"))
    c_short = S1.LAWS["vocab_cluster"](r, S1.base_opts(np=None, auth=None))
    pc = 0
    for c in (c_long, c_short):
        r2 = dict(r)
        r2["block"] = true_block(c)
        mixed_old = __import__("_sub_ios_claims2_oracle").oracle_batch(
            r2, [c_long, c_short])
        mixed_new = oracle_batch_fixed(r2, [c_long, c_short])
        want = np.zeros(2, dtype=bool)
        want[0 if c is c_long else 1] = True
        pc += int(bool((mixed_new == want).all())
                  and not (np.array(mixed_old) == want).all())
    return golds_ok, pc


if __name__ == "__main__":
    g, p = selftest()
    print("android golds via fixed oracle: %d/9" % g)
    print("forged-hit positive controls (old misses, fixed finds): %d/2" % p)
