"""_sub_claims3_search3.py — claims3 stage 6: cross the NEW claims space
(network_payload / authorization / signature / corrected key lists) with the
BLOCK-frame dimension (D9 slot x magic slot x tail slot) via a generic-tail
oracle.  The prior stage's frame matrix (~800 frames) was only ever combined
with the OLD pool; this closes that gap.
"""
import struct
import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_signer as sg
import _sub_np_sha256 as npsha
import _sub_claims3_search as S1

SHA0 = sg.SHA0

TAILS = {
    "02+dev": lambda r: bytes([0x02]) + r["dev"],
    "01+00*16": lambda r: b"\x01" + b"\x00" * 16,
    "02+00*16": lambda r: b"\x02" + b"\x00" * 16,
    "01+dev": lambda r: b"\x01" + r["dev"],
    "06+dev": lambda r: b"\x06" + r["dev"],
    "07+dev": lambda r: b"\x07" + r["dev"],
    "dev+02": lambda r: r["dev"] + b"\x02",
    "0207+00*15": lambda r: b"\x02\x07" + b"\x00" * 15,
    "rec111_130": lambda r: r["rec"][111:130],
    "dev_only": lambda r: r["dev"],
}
D9S = {"zeros20": lambda r: b"\x00" * 20, "empty": lambda r: b"",
       "devpad": lambda r: (r["dev"] + b"\x00" * 4)}
MAGICS = {"0008": b"\x00\x08", "0100": b"\x01\x00"}


def oracle_frames(rec, claims_list, d9, magic, tail_bytes):
    """Generic sha256-IV2 oracle: d9 || magic || head16 || LE32(S) ||
    sha256("") || tail_bytes || claims."""
    head = d9 + magic + rec["head16"] + struct.pack("<I", rec["S"]) + SHA0
    msg_head = head + tail_bytes
    pref = msg_head[:64]
    rest0 = msg_head[64:]
    target = np.frombuffer(rec["block"], ">u4").astype(np.uint32)
    L0 = len(msg_head)
    rows = []
    for c in claims_list:
        c = c.encode("latin1") if isinstance(c, str) else bytes(c)
        total = L0 + len(c)
        t = c + b"\x80" + b"\x00" * ((55 - total) % 64) \
            + struct.pack(">Q", total * 8)
        rows.append(np.frombuffer(t, np.uint8))
    T = max(len(x) for x in rows)
    if T % 64:
        T += 64 - T % 64
    rests = np.zeros((len(rows), T), dtype=np.uint8)
    for i, x in enumerate(rows):
        rests[i, :len(x)] = x
    words = npsha.batch_digests(pref, rests)
    return (words == target).all(axis=1)


def selftest_oracle():
    """Reproduce the 9 Android gold blocks through oracle_frames (Android
    frame: real D9, 0008, tail 01||00*16)."""
    ok = 0
    for g in sg.GOLD_VECTORS:
        blob = bytes.fromhex(g["blob_hex"])
        recb = sg.whiten_inverse(blob[16:160], blob[:16]) \
            if hasattr(sg, "whiten_inverse") else None
        from _sub_unseal_core import whiten_inverse
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
        arr = oracle_frames(rec, [claims], bytes.fromhex(g["d9_hex"]),
                            b"\x00\x08", b"\x01" + b"\x00" * 16)
        ok += int(arr[0])
    return ok


RESULTS = {"stages": {}, "hits": []}


def run_stage6(name, records, opts, law_names, note=""):
    n = 0
    hits = []
    frames = [(dn, mn, tn) for dn in D9S for mn in MAGICS for tn in TAILS]
    for r in records:
        for dn, mn, tn in frames:
            d9 = D9S[dn](r)
            magic = MAGICS[mn]
            tail = TAILS[tn](r)
            claims_list = []
            meta = []
            for opt in opts:
                for ln in law_names:
                    claims_list.append(S1.LAWS[ln](r, opt))
                    meta.append((ln, json.dumps(opt, sort_keys=True)))
            for i0 in range(0, len(claims_list), 20000):
                chunk = claims_list[i0:i0 + 20000]
                arr = np.array(oracle_frames(r, chunk, d9, magic, tail))
                n += len(chunk)
                for i in np.nonzero(arr)[0]:
                    gi = i0 + int(i)
                    h = {"file": r["file"], "kind": r["kind"], "law": meta[gi][0],
                         "opt": meta[gi][1], "frame": "%s|%s|%s" % (dn, mn, tn),
                         "claims": chunk[i].decode("latin1", "replace")}
                    hits.append(h)
                    RESULTS["hits"].append(h)
                    print("  *** HIT:", h, flush=True)
    RESULTS["stages"][name] = {"n": n, "hits": hits, "note": note}
    print("[stage %s] %d candidates, %d hits" % (name, n, len(hits)),
          flush=True)
    with open(os.path.join(HERE, "_sub_claims3_out.json"), "w") as f:
        json.dump(RESULTS, f, indent=1)
    return hits


def main():
    ok = selftest_oracle()
    print("generic-frame oracle on android golds: %d/9" % ok, flush=True)
    if ok != 9:
        print("ORACLE BROKEN — abort", flush=True)
        sys.exit(1)
    corpus = S1.load_corpus()
    opts = [S1.base_opts(np="body", auth="nosig"),
            S1.base_opts(np="dec", auth="nosig"),
            S1.base_opts(np="body", auth="nosig", os_name="sim"),
            S1.base_opts(np=None, auth="nosig"),
            S1.base_opts(np="body", auth="emptysig"),
            S1.base_opts(np="body", auth="nosig_ns")]
    laws = ["sorted_split", "sorted_one", "hint5_prefix", "hint5_suffix",
            "dict6_prefix", "dict6_suffix", "authhdr6_prefix",
            "authhdr6_suffix", "wire_order_end", "vocab_cluster",
            "cluster_prefix"]
    run_stage6("6_frames_x_newclaims", corpus, opts, laws,
               note="30 frames (D9 x magic x tail) x 6 new-key bindings x "
                    "11 laws, all 30 records")
    total = sum(s["n"] for s in RESULTS["stages"].values())
    print("TOTAL stage6: %d candidates, %d hits" % (total, len(hits)),
          flush=True)


if __name__ == "__main__":
    main()
