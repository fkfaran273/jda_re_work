"""block_law.py — hunt the generating law of record[46:78) in the adj9 signature.

The 144-B adj9 record has exactly one byte range whose law is unknown: the
32-B block at [46:78) (tag 0x04 in the record's tag/length stream).  This script
builds the sample set (6 genuine winning blobs + 8 corpus blobs), rebuilds the
full region for each from S via F.py, verifies the region law, and then tests
candidate laws for the block.

Run:  python block_law.py            # full search
      python block_law.py --samples  # just dump the samples
"""
from __future__ import annotations

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

import F as Fmod  # noqa: E402
import whiten_decoder as WD  # noqa: E402

# --------------------------------------------------------------------------
# sample set
# --------------------------------------------------------------------------
# Winning device head phases (win_decode_analysis.md §3): prefix selectors
# then the stable cycle CY(i) = 0x40 | (i & 7) resuming at index 2.
WIN_HEAD_FIRST = (0x2B, 0x41)
WIN_HEAD_RESIGN = (0x2B, 0x48)


def _phase_selectors(prefix):
    return tuple(prefix[i] if i < len(prefix) else (0x40 | (i & 7))
                 for i in range(72))


def make_samples():
    """Return a list of dicts, one per (record, region) observation."""
    out = []

    # ---- 1. the 6 genuine winning blobs --------------------------------
    W = json.load(open(os.path.join(HERE, "win_capture", "winning_material.json")))
    log = open(os.path.join(HERE, "win_capture", "module_win_capture.log"),
               encoding="utf-8", errors="replace").read()
    sigs = re.findall(r'signature="([A-Za-z0-9+/=]+)"', log)
    tss = [int(t) for t in re.findall(
        r"###ADJ9_BEGIN type=authorization_header utf8len=407 ts=(\d+)", log)]
    for i, bh in enumerate(W["blobs"]):
        blob = bytes.fromhex(bh)
        assert blob == base64.b64decode(sigs[i]), "blob %d != log signature" % i
        dec = WD.decode_blob(blob)
        seed = dec["F_seed"]
        rec = dec["record"]
        head_vals = [int.from_bytes(rec[3 + 2 * j:5 + 2 * j], "big")
                     for j in range(8)]
        d4w = Fmod._d4_words(seed)
        src = Fmod._d0_source(d4w)
        # solve the prefix phase from the head values
        ph = None
        for name, pfx in (("WIN_FIRST", WIN_HEAD_FIRST),
                          ("WIN_RESIGN", WIN_HEAD_RESIGN)):
            sels = _phase_selectors(pfx)
            if all(Fmod._selector_halfword((sels[j] << 1) + 3, src) == head_vals[j]
                   for j in range(8)):
                ph = (name, sels)
                break
        d0w = Fmod._d0_words(d4w, head=tuple(ph[1][:2]) if ph else None)
        out.append(dict(
            tag="win%d" % i, blob=blob, record=rec, seed=seed,
            d2w=dec["d2w"], d0w=d0w, d4w=d4w,
            d0=b"".join(w.to_bytes(4, "big") for w in d0w),
            d4=b"".join(w.to_bytes(4, "big") for w in d4w),
            d2=dec["d2w"].to_bytes(4, "big"),
            block=rec[46:78], second=tss[i] // 1000 if i < len(tss) else None,
            phase=ph[0] if ph else None,
        ))

    # ---- 2. the 8 corpus blobs ------------------------------------------
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    for r in ph3:
        blob = bytes.fromhex(r["blob"])
        dec = WD.decode_blob(blob)
        seed = dec["F_seed"]
        rec = dec["record"]
        d4w = Fmod._d4_words(seed)
        # phase: match the record head against the corpus device's phases
        ph = None
        for name, pfx in (("HEAD_FIRST", Fmod.HEAD_FIRST),
                          ("HEAD_RESIGN", Fmod.HEAD_RESIGN),
                          ("WIN_FIRST", WIN_HEAD_FIRST),
                          ("WIN_RESIGN", WIN_HEAD_RESIGN)):
            sels = _phase_selectors(pfx)
            d0w = Fmod._d0_words(d4w, head=pfx)
            if WD.head_words(d0w) == rec[3:19]:
                ph = (name, sels)
                break
        d0w = Fmod._d0_words(d4w, head=ph[1][:2] if ph else None)
        out.append(dict(
            tag="cor%d" % r["i"], blob=blob, record=rec, seed=seed,
            d2w=dec["d2w"], d0w=d0w, d4w=d4w,
            d0=b"".join(w.to_bytes(4, "big") for w in d0w),
            d4=b"".join(w.to_bytes(4, "big") for w in d4w),
            d2=dec["d2w"].to_bytes(4, "big"),
            block=rec[46:78], second=int(r["second"]),
            phase=ph[0] if ph else None,
            H=bytes.fromhex(r["H"]),
        ))
    return out


def region_from_S_seed(seed, pid):
    return Fmod.region(seed ^ ((pid & 0xFFFF) << 16), pid)


# --------------------------------------------------------------------------
# candidate laws
# --------------------------------------------------------------------------
def candidate_material(s):
    """Every named byte string we might hash / copy."""
    seed, d2w = s["seed"], s["d2w"]
    d0b, d4b = s["d0"], s["d4"]
    head = s["record"][3:19]
    S_be = s["record"][20:24]
    S_le = bytes(reversed(S_be))
    m = {
        "S_be": S_be,
        "S_le": S_le,
        "S_le32": d2w.to_bytes(4, "big"),
        "S_be32": seed.to_bytes(4, "big"),
        "d0": d0b,
        "d0_16": d0b[:16],
        "d0_4": d0b[:4],
        "d4": d4b,
        "d4_16": d4b[:16],
        "d4_hi": d4b[:16],
        "d4_lo": d4b[16:],
        "head": head,
        "head+S": head + S_be,
        "S+head": S_be + head,
        "d4+head": d4b + head,
        "head+d4": head + d4b,
        "d0+d4": d0b + d4b,
        "d0[4:]+S": d0b[16:] + S_be,
        "S^head": bytes(a ^ b for a, b in zip(S_be, head)),
        "S^head16": bytes(a ^ b for a, b in zip((S_be * 4)[:16], head)),
        "head^d4": bytes(a ^ b for a, b in zip((head * 2), d4b[:32])),
        "rec03_46": s["record"][3:46],
        "rec0_46": s["record"][0:46],
        "rec3_24": s["record"][3:24],
        "rec0_24": s["record"][0:24],
        "rec0_45": s["record"][0:45],
        "rec0_78_zero": s["record"][0:46] + b"\0" * 32,
        "SLE": struct.pack("<I", seed),
        "SLE_x2": struct.pack("<II", seed, seed),
    }
    # d0 word views
    m["d0w_le"] = b"".join(struct.pack("<I", w) for w in s["d0w"])
    m["d4w_le"] = b"".join(struct.pack("<I", w) for w in s["d4w"])
    m["d0w_le32"] = m["d0w_le"][:32]
    # the raw materializer intermediates
    raw = Fmod._raw16(seed)
    packed = b"".join(x.to_bytes(2, "little") for x in raw)
    m["raw16_le"] = packed
    m["raw16_be"] = b"".join(x.to_bytes(2, "big") for x in raw)
    m["d4_words_le"] = b"".join(w.to_bytes(4, "little") for w in s["d4w"])
    m["d4_pack_le"] = packed
    return m


def test(samples):
    """Try every candidate law; report exact multi-sample hits."""
    hits = {}

    def rec(name, fn):
        ok = 0
        for s in samples:
            try:
                v = fn(s)
            except Exception:
                v = None
            if v == s["block"]:
                ok += 1
        if ok:
            hits[name] = ok

    H = {
        "sha256": lambda b: hashlib.sha256(b).digest(),
        "sha1": lambda b: hashlib.sha1(b).digest()[:32],
        "md5x2": lambda b: hashlib.md5(b).digest() + hashlib.md5(
            hashlib.md5(b).digest()).digest(),
        "sha512_lo": lambda b: hashlib.sha512(b).digest()[:32],
        "sha224_pad": lambda b: hashlib.sha224(b).digest() + b"\0" * 8,
    }
    for aname, afn in H.items():
        for mname in candidate_material(samples[0]):
            rec("%s(%s)" % (aname, mname), lambda s, f=afn, k=mname: f(
                candidate_material(s)[k]))
        # hmac variants
        for mname in ("S_be", "S_le", "head", "d0_4", "d0_16", "d4", "d4_16",
                      "d0", "S_be32", "S_le32", "d0w_le32", "rec3_24"):
            for kname in ("S_be", "S_le", "head", "d4", "d0", "d0_4", "rec0_24",
                          "S_be32"):
                rec("hmac(%s,%s)" % (kname, mname),
                    lambda s, k=kname, m=mname: hmac.new(
                        candidate_material(s)[k],
                        candidate_material(s)[m], hashlib.sha256).digest())
    # raw / structural equality
    for s0 in samples[:1]:
        for mname, val in candidate_material(s0).items():
            rec("raw:%s" % mname, lambda s, k=mname: candidate_material(s)[k])
            rec("raw:%s||:32" % mname, lambda s, k=mname: candidate_material(s)[k] * 2)
    return hits


def main():
    samples = make_samples()
    print("=== samples: %d ===" % len(samples))
    for s in samples:
        print("%-6s sec=%-11s S=%08x d2=%08x phase=%-10s consts=%s"
              % (s["tag"], s["second"], s["seed"], s["d2w"], s["phase"],
                 WD.record_checks(s["record"])))
        print("       head=%s" % s["record"][3:19].hex())
        print("       block=%s" % s["block"].hex())
    if "--samples" in sys.argv:
        return

    print()
    print("=== region check: F._d4_words(S) / d2 ===")
    for s in samples:
        okd2 = s["record"][20:24] == s["seed"].to_bytes(4, "big")
        okh = WD.head_words(s["d0w"]) == s["record"][3:19]
        print("%-6s d2_be(S)=%-5s head_match=%-5s phase=%s"
              % (s["tag"], okd2, okh, s["phase"]))

    print()
    print("=== candidate law search ===")
    hits = test(samples)
    if not hits:
        print("no candidate matched")
    for k, v in sorted(hits.items(), key=lambda kv: -kv[1]):
        print("%-40s %d/%d" % (k, v, len(samples)))


if __name__ == "__main__":
    main()
