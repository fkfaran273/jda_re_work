"""win_decode_analysis.py — decode the 6 genuine winning adj9 blobs, compare
their regions against F.py synthesis, and locate the genuine-vs-synthetic
difference.

Run:  python win_decode_analysis.py
Outputs win_decode_results.json (win_decode_analysis.md is hand-written).
"""
import base64
import hashlib
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from whiten_decoder import decode_blob, D9, SHA0
import F as Fmod

WIN = os.path.join(HERE, "win_capture")

bs16 = lambda v: ((v & 0xFF) << 8) | (v >> 8)
CY = lambda i: 0x40 | (i & 7)


def head_values_from_record(head_bytes):
    """record[3:19) -> the 8 head halfword VALUES (each stored BE16)."""
    out = []
    for k in range(0, 16, 2):
        out.append(int.from_bytes(head_bytes[k:k + 2], "big"))
    return out


def head_words_be16(values):
    """the 8 head halfword values -> record[3:19) (each value stored BE16)."""
    return b"".join(v.to_bytes(2, "big") for v in values)


def d0_words_from_selectors(d4, selectors):
    source = Fmod._d0_source(d4)
    values = [Fmod._selector_halfword((s << 1) + 3, source) for s in selectors]
    raw = b"".join(v.to_bytes(2, "little") for v in values)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 144, 4)]


# head-phase selector tables (first 8 selectors produce the record head)
PHASES = {
    "WIN_HEAD_FIRST (0x2B,0x41)+CY@2":
        (0x2B, 0x41) + tuple(CY(i) for i in range(2, 72)),
    "WIN_HEAD_RESIGN (0x2B,0x48)+CY@2":
        (0x2B, 0x48) + tuple(CY(i) for i in range(2, 72)),
    "corpus HEAD_FIRST (0x22,0x2E)+CY@2":
        (0x22, 0x2E) + tuple(CY(i) for i in range(2, 72)),
    "corpus HEAD_RESIGN (0x2B,0x07,0x22,0x2E)+CY@4":
        (0x2B, 0x07, 0x22, 0x2E) + tuple(CY(i) for i in range(4, 72)),
    "synth (0x2B,0x22,0x25,0x2E)+CY@4":
        (0x2B, 0x22, 0x25, 0x2E) + tuple(CY(i) for i in range(4, 72)),
    "synth (0x2B,0x07,0x22,0x25,0x2E)+CY@5":
        (0x2B, 0x07, 0x22, 0x25, 0x2E) + tuple(CY(i) for i in range(5, 72)),
}

# ---------------------------------------------------------------------------
# 1. parse the log
# ---------------------------------------------------------------------------
L = (open(os.path.join(WIN, "module_win_capture.log"), encoding="utf-8",
          errors="replace").read()
     .replace("\r\r\n", "\n").replace("\r\n", "\n").replace("\r", "\n"))
L = re.sub(r"\n+", "\n", L)

auth = [{"ts": int(m.group(1)), "blob": base64.b64decode(m.group(2))}
        for m in re.finditer(
            r'###ADJ9_BEGIN type=authorization_header[^\n]*ts=(\d+)\n'
            r'text: Signature signature="([A-Za-z0-9+/=]+)"', L)]
t1out = [{"ts": int(m.group(1)), "hex": m.group(2)}
         for m in re.finditer(
             r'###ADJ9_BEGIN type=t1_a_out[^\n]*ts=(\d+)\ntext: len=32\n'
             r'hex=([0-9a-f]+)', L)]
nsign_native = [{"ts": int(m.group(1)), "hex": m.group(2)}
                for m in re.finditer(
                    r'###ADJ9_BEGIN type=nsign_native[^\n]*ts=(\d+)\n'
                    r'text: [^\n]*\nout_hex=([0-9a-f]+)', L)]
t1in = [{"ts": int(m.group(1)), "th": m.group(2)}
        for m in re.finditer(
            r'###ADJ9_BEGIN type=t1_a_in[^\n]*ts=(\d+)\ntext: th=([^\n]*)', L)]
sign_input = []
for m in re.finditer(r'###ADJ9_BEGIN type=sign_input[^\n]*ts=(\d+)\n'
                     r'([\s\S]{0,9000}?)###ADJ9_END', L):
    kind = re.search(r'activity_kind=(\w+)', m.group(2))
    sign_input.append({"ts": int(m.group(1)),
                       "kind": kind.group(1) if kind else None})

print("parsed: %d auth, %d t1_a_out, %d nsign_native, %d t1_a_in, "
      "%d sign_input" % (len(auth), len(t1out), len(nsign_native),
                         len(t1in), len(sign_input)))

# ---------------------------------------------------------------------------
# 2. decode + identify head phase + F.py comparison
# ---------------------------------------------------------------------------
results = []
for i, a in enumerate(auth):
    d = decode_blob(a["blob"])
    rec = d["record"]
    seed = d["F_seed"]                      # = byteswap(d2w) = native seed
    d2w = d["d2w"]
    d4 = Fmod._d4_words(seed)
    src = Fmod._d0_source(d4)
    hv = head_values_from_record(rec[3:19])
    sel_found = []
    for j, v in enumerate(hv):
        hits = [s for s in range(128)
                if Fmod._selector_halfword((s << 1) + 3, src) == v]
        sel_found.append(hits)
    phase = None
    phase_full = None
    for name, sel in PHASES.items():
        if head_words_be16(
                [Fmod._selector_halfword((s << 1) + 3, src)
                 for s in sel[:8]]) == rec[3:19]:
            phase = name
            phase_full = sel
    # F.py region() with the winning phase, pid=0 (seed taken from the record)
    d2_f = int.from_bytes(seed.to_bytes(4, "little"), "big")
    d0w = d0_words_from_selectors(d4, phase_full) if phase_full else None
    d0w_f = Fmod._d0_words(d4, head=None)   # F.py default HEAD_FIRST
    prev = [t for t in t1out if t["ts"] <= a["ts"]]
    tin = [t for t in t1in if t["ts"] <= a["ts"] and a["ts"] - t["ts"] < 3000]
    kind = None
    for si in sign_input:
        if abs(si["ts"] - a["ts"]) < 3000:
            kind = si["kind"]
    results.append({
        "i": i,
        "ts": a["ts"],
        "second": a["ts"] // 1000,
        "activity_kind": kind,
        "signer_thread": tin[-1]["th"] if tin else None,
        "consts_ok": d["consts_ok"],
        "cert_ok": rec[25:45] == D9,
        "sha0_ok": rec[79:111] == SHA0,
        "tail2": d["tail2"].hex(),
        "header": d["header"].hex(),
        "tail32": a["blob"][160:192].hex(),
        "block": d["block"].hex(),
        "S_seed": seed,
        "d2w": d2w,
        "head": d["head"].hex(),
        "head_values": ["%04x" % v for v in hv],
        "head_selector_sets": [["%02x" % s for s in h] for h in sel_found],
        "phase": phase,
        "d2_fpy_match": d2_f == d2w,
        "d4w_fpy": ["%08x" % w for w in d4],
        "d0w0_fpy_with_phase": ["%08x" % w for w in d0w[:4]] if d0w else None,
        "head_reproduced": phase is not None,
        "head_reproduced_fpy_HEAD_FIRST":
            head_words_be16([Fmod._selector_halfword((s << 1) + 3, src)
                             for s in PHASES["corpus HEAD_FIRST (0x22,0x2E)"
                                             "+CY@2"][:8]]) == rec[3:19],
        "head_reproduced_fpy_HEAD_RESIGN":
            head_words_be16([Fmod._selector_halfword((s << 1) + 3, src)
                             for s in PHASES["corpus HEAD_RESIGN (0x2B,0x07,"
                                             "0x22,0x2E)+CY@4"][:8]])
            == rec[3:19],
        "block_is_payload_hmac": (prev and d["block"].hex() == prev[-1]["hex"]),
        "t1_a_out_hex": prev[-1]["hex"] if prev else None,
        "nsign_native_match": any(n["hex"] == a["blob"].hex()
                                  for n in nsign_native),
    })

print()
print("=== per-blob results ===")
for r in results:
    print("blob %d: sec=%d %-12s thread=%s" % (r["i"], r["second"],
                                               r["activity_kind"],
                                               r["signer_thread"]))
    print("   consts=%s cert=%s S=%08x d2w=%08x d2_fpy=%s"
          % (r["consts_ok"], r["cert_ok"], r["S_seed"], r["d2w"],
             r["d2_fpy_match"]))
    print("   head=%s" % r["head"])
    print("   values=%s" % " ".join(r["head_values"]))
    print("   selector sets=%s" % r["head_selector_sets"])
    print("   phase=%s  head_reproduced=%s  (F.py HEAD_FIRST: %s, "
          "HEAD_RESIGN: %s)"
          % (r["phase"], r["head_reproduced"],
             r["head_reproduced_fpy_HEAD_FIRST"],
             r["head_reproduced_fpy_HEAD_RESIGN"]))
    print("   block=%s.. block==payloadHMAC:%s tail2=%s tail32=%s.."
          % (r["block"][:16], r["block_is_payload_hmac"], r["tail2"],
             r["tail32"][:16]))

# ---------------------------------------------------------------------------
# 3. corpus cross-check (known regions, HEAD_FIRST device)
# ---------------------------------------------------------------------------
ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
corpus = []
for row in ph3:
    dec = decode_blob(bytes.fromhex(row["blob"]))
    seed = dec["F_seed"]
    d4 = Fmod._d4_words(seed)
    src = Fmod._d0_source(d4)
    hv = head_values_from_record(dec["record"][3:19])
    sels = []
    for v in hv:
        hits = [s for s in range(128)
                if Fmod._selector_halfword((s << 1) + 3, src) == v]
        sels.append(["%02x" % s for s in hits])
    corpus.append({
        "i": row["i"], "second": row["second"], "S_seed": seed,
        "d2w": dec["d2w"], "head": dec["head"].hex(),
        "head_selector_sets": sels,
        "block": dec["block"].hex(), "tail2": dec["tail2"].hex(),
        "header": dec["header"].hex(),
        "tail32": bytes.fromhex(row["blob"])[160:192].hex(),
        "region_match_all_signings":
            dec["region"] is not None
            and dec["region"]["d0"].hex() == row["d0"]
            and dec["region"]["d4"].hex() == row["d4"],
    })

print()
print("=== corpus cross-check (genuine test device) ===")
for c in corpus:
    sels = [h[0] if h else "??" for h in c["head_selector_sets"]]
    print("row %d: S=%08x region_match=%s head sels=%s"
          % (c["i"], c["S_seed"], c["region_match_all_signings"],
             " ".join(sels)))

# ---------------------------------------------------------------------------
# 4. S pattern
# ---------------------------------------------------------------------------
seeds = [r["S_seed"] for r in results]
print()
print("=== S pattern across the 6 winning signings ===")
for r in results:
    print("blob %d: sec=%d S=%08x (%d)" % (r["i"], r["second"], r["S_seed"],
                                           r["S_seed"]))
print("deltas:", [hex(seeds[k] - seeds[k - 1]) for k in range(1, 6)])
print("distinct:", len(set(seeds)) == 6)

# ---------------------------------------------------------------------------
# 5. block/tail2/tail32 hash hunt (corpus has fully known regions)
# ---------------------------------------------------------------------------
def H(x):
    return hashlib.sha256(x).digest()


print()
print("=== hash hunt for block[46:78) and tail32 (known-region corpus rows) ===")
for c in corpus:
    row = next(p for p in ph3 if p["i"] == c["i"])
    dec = decode_blob(bytes.fromhex(row["blob"]))
    d0 = bytes.fromhex(row["d0"])
    d2le = bytes.fromhex(row["d2"])
    d4 = bytes.fromhex(row["d4"])
    head = bytes.fromhex(c["head"])
    blob = bytes.fromhex(row["blob"])
    rec = dec["record"]
    parts = {"seedbe": c["S_seed"].to_bytes(4, "big"),
             "seedle": c["S_seed"].to_bytes(4, "little"),
             "d4": d4, "d0": d0, "head": head, "d2le": d2le,
             "head+d2le": head + d2le, "head+d2le+d4": head + d2le + d4,
             "d0+d2le+d4": d0 + d2le + d4, "d4+d0": d4 + d0}
    bhits = []
    thits = []
    for n, p in parts.items():
        for tag, val in (("sha256", H(p)), ("sha2x", H(H(p))),
                         ("sha256+0e14", H(p + b"\x0e" * 14))):
            if val.hex() == c["block"]:
                bhits.append("%s(%s)" % (tag, n))
            if val.hex() == c["tail32"]:
                thits.append("%s(%s)" % (tag, n))
    for n, p in (("blob0_160", blob[:160]), ("record", rec),
                 ("rec0_130", rec[:130]), ("rec0_128", rec[:128]),
                 ("rec0_111", rec[:111]), ("rec0_79", rec[:79]),
                 ("rec0_46", rec[:46]), ("head+rec", rec)):
        if H(p).hex() == c["tail32"]:
            thits.append("sha256(%s)" % n)
    print("row %d: block hits=%s tail32 hits=%s" % (c["i"], bhits, thits))

# ---------------------------------------------------------------------------
# 6. collect results
# ---------------------------------------------------------------------------
out = {
    "source_log": "win_capture/module_win_capture.log",
    "n_blobs": len(results),
    "winning_blobs": results,
    "corpus": corpus,
    "phases": {k: ["%02x" % s for s in v[:8]] for k, v in PHASES.items()},
    "findings": {
        "S": "record stores the seed BIG-endian at [20:24); the d2 descriptor "
             "word = byteswap(seed); 6 distinct draws, not time-correlated, "
             "not V^(pid<<16)",
        "d2": "F.py region d2 == byteswap(seed) == d2w for all 6",
        "d4": "not carried in the blob; confirmed via head selector "
              "consistency over _d0_source(_d4_words(S)) for all 6 blobs",
        "d0_head": "record head = 8 halfword values stored BE16 in selector "
                   "call order; winning device phases WIN_HEAD_FIRST "
                   "(0x2B,0x41) and WIN_HEAD_RESIGN (0x2B,0x48), both "
                   "+ stable cycle CY(i)=0x40|(i&7) from i=2",
        "phase_correlation": "WIN_HEAD_RESIGN rows were signed by the "
                             "adj9-chosen-sign re-sign path; WIN_HEAD_FIRST "
                             "rows by fresh Signer.nSign sender threads",
        "block": "32-B block [46:78) is VM-computed hash material "
                 "(not the payload HMAC, no sha256 preimage found); only "
                 "fin_vm2 reproduces it",
        "tail2": "0000 in all 14 observations (6 win + 8 corpus)",
        "tail32": "blob[160:192) separate digest; no simple hash preimage",
    },
}

# ---------------------------------------------------------------------------
# 7. header model + end-to-end synthesis proof + poisoned-row cross-check
# ---------------------------------------------------------------------------
from header_gen import make_header
from whiten_decoder import whiten_forward, whiten_body_inverse

print()
print("=== header model make_header(unix_sec) ===")
for r in results:
    sec = 1790341508 + r["i"]
    r["header_model"] = make_header(sec).hex()
    r["header_match"] = r["header_model"] == r["header"]
    print("blob %d: make_header(%d) match=%s" % (r["i"], sec,
                                                 r["header_match"]))
for c in corpus:
    c["header_model"] = make_header(c["second"]).hex()
    c["header_match"] = c["header_model"] == c["header"]

print()
print("=== end-to-end synthesis proof (second, S, phase) -> record ===")
for r in results:
    blob = base64.b64decode(re.findall(
        r'text: Signature signature="([A-Za-z0-9+/=]+)"', L)[r["i"]])
    rec_g = whiten_body_inverse(blob[16:160], blob[:16])
    seed = r["S_seed"]
    d4 = Fmod._d4_words(seed)
    src = Fmod._d0_source(d4)
    phase = (0x2B, 0x41) if r["phase"].startswith("WIN_HEAD_FIRST") \
        else (0x2B, 0x48)
    sel = phase + tuple(CY(j) for j in range(2, 72))
    head = b"".join(Fmod._selector_halfword((s << 1) + 3, src)
                    .to_bytes(2, "big")
                    for s in sel[:8])
    rec = (b"\x01\x00\x08" + head + b"\x02" + seed.to_bytes(4, "big")
           + b"\x03" + D9 + b"\x04" + rec_g[46:78] + b"\x05" + SHA0
           + b"\x06\x01\x07" + b"\x00" * 14 + b"\x00\x00" + b"\x0e" * 14)
    body = whiten_forward(rec, make_header(r["second"]))
    r["record_synthesized"] = rec == rec_g
    r["whitened_body_synthesized"] = body == blob[16:160]
    r["d2_record_bytes"] = "seed stored BIG-endian in record; d2 descriptor "
    "word = byteswap(seed)"
    print("blob %d: record==genuine=%s whitened-body==genuine=%s "
          "(block bytes borrowed)" % (r["i"], r["record_synthesized"],
                                      r["whitened_body_synthesized"]))

print()
print("=== poisoned win_rows full-d0 cross-check ===")
wr = json.load(open(os.path.join(WIN, "win_rows.json")))
PH_POISON = {
    "poison_first": (0x2B, 0x22, 0x25, 0x2E) + tuple(CY(j) for j in range(4, 72)),
    "poison_resign": (0x2B, 0x07, 0x22, 0x25, 0x2E)
                     + tuple(CY(j) for j in range(5, 72)),
}
poison_results = []
for ri, rw in enumerate(wr["rows"]):
    S = rw["S"]
    d0hex = rw["desc"]["0"]["hex"]
    d4hex = rw["desc"]["4"]["hex"]
    d4 = Fmod._d4_words(S)
    d4ok = b"".join(w.to_bytes(4, "big") for w in d4).hex() == d4hex
    src = Fmod._d0_source(d4)
    hit = None
    for name, sel in PH_POISON.items():
        vals = [Fmod._selector_halfword((s << 1) + 3, src) for s in sel]
        raw = b"".join(v.to_bytes(2, "little") for v in vals)
        d0b = b"".join(int.from_bytes(raw[j:j + 4], "big").to_bytes(4, "big")
                       for j in range(0, 144, 4))
        if d0b.hex() == d0hex:
            hit = name
    poison_results.append({"row": ri, "sign_id": rw["sign_id"], "S": S,
                           "d4_match": d4ok, "d0_phase": hit})
    print("row %d sign_id=%s: d4_match=%s d0 phase=%s"
          % (ri, rw["sign_id"], d4ok, hit))

out["header_model"] = "make_header(unix_sec) matches all 6 win + 8 corpus " \
                      "blob headers"
out["poisoned_rows"] = poison_results
with open(os.path.join(HERE, "win_decode_results.json"), "w") as f:
    json.dump(out, f, indent=1)
print()
print("saved win_decode_results.json")
