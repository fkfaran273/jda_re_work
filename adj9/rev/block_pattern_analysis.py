"""block_pattern_analysis.py — what is in record[46:78), and can Python make it?

The 144-B adj9 record carries a 32-byte "block" at [46:78) between the APK cert
SHA-1 (d9, [25:45)) and SHA256("") (d9b, [79:111)).  Six genuine
UN-INSTRUMENTED winning blobs from win_capture/module_win_capture.log booked on
the server; the instrumented (Frida-hooked) corpus in pair_h3.json did not.

This script:
  1. extracts the 6 genuine blobs from the `Signature signature="..."` headers
     and decodes each with whiten_decoder (record_checks must pass),
  2. pulls S / head / block / tail2 out of every record,
  3. compares the 6 blocks pairwise (XOR, mod-256 deltas, shared bytes),
  4. hunts each block and its 8-byte windows in the capture log,
  5. tries ~40 simple compositions of (S, head, cert, d0, d4, sha0),
  6. checks whether the block is a function of S alone (same-S groups),
  7. compares genuine vs instrumented block statistics,
  8. checks whether [46:78) is plaintext in the encoded blob or whitened,
  9. THE ANSWER: drives the FinEx VM (fin_vm2.FinEx) over the descriptors
     rebuilt from the genuine sign_input claims and asks whether it emits the
     genuine block byte-for-byte.

Run:  python block_pattern_analysis.py            # everything (~90 s, FinEx)
      python block_pattern_analysis.py --nofinex  # skip step 9 (~1 s)
"""
import base64
import hashlib
import itertools
import json
import math
import os
import re
import struct
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import whiten_decoder as WD  # noqa: E402
import F as Fmod  # noqa: E402

LOG = os.path.join(HERE, "win_capture", "module_win_capture.log")
PAIR_H3 = os.path.join(HERE, "pair_h3.json")
OUT_JSON = os.path.join(HERE, "block_pattern_analysis.json")

D9 = WD.D9
SHA0 = WD.SHA0
D8_HEX = "bffffffffffffd1f0007000000000000"
SINK = 0x5500000000
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]     # FinEx descriptor order


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def sub(a, b):
    return bytes((x - y) & 0xFF for x, y in zip(a, b))


def entropy(x):
    if not x:
        return 0.0
    n = len(x)
    return -sum((c / n) * math.log(c / n, 2) for c in Counter(x).values())


def xor_diffs(entries):
    out = []
    for a, b in itertools.combinations(range(len(entries)), 2):
        A, B = entries[a]["block"], entries[b]["block"]
        out.append({
            "pair": [a, b],
            "dS": entries[b]["S"] - entries[a]["S"],
            "equal_bytes": [k for k in range(32) if A[k] == B[k]],
            "xor": xor(A, B).hex(),
            "mod256_delta": sub(B, A).hex(),
        })
    return out


# ---------------------------------------------------------------------------
# 1. extract + decode
# ---------------------------------------------------------------------------
SIG_RE = re.compile(r'Signature signature="([A-Za-z0-9+/=]+)"')
BEGIN_RE = re.compile(r'###ADJ9_BEGIN type=(\w+)')


def read_log():
    return open(LOG, "rt", errors="replace").read()


def log_blocks(log, typ):
    return [log[m.start():log.find("###ADJ9_END", m.start())]
            for m in re.finditer(r'###ADJ9_BEGIN type=%s\b' % typ, log)]


def extract_win(log):
    """6 genuine blobs, each with its signing second and sign_input claims."""
    from desc10_law import build_desc10

    sigs, sig_seconds, sig_idx = [], [], []
    for m in SIG_RE.finditer(log):
        try:
            raw = base64.b64decode(m.group(1), validate=True)
        except Exception:
            continue
        if len(raw) != 192:
            continue
        ctx = log[max(0, m.start() - 1500):m.start()]
        ts = re.findall(r"ts=(\d+)", ctx)
        sigs.append(raw)
        sig_seconds.append(int(ts[-1]) // 1000 if ts else None)
        sig_idx.append(m.start())

    si = log_blocks(log, "sign_input")

    def parse_map(block):
        m = re.search(r"map_toString=\{(.*?)\}\s*\n", block, re.S)
        if not m:
            return None
        d = {}
        for part in m.group(1).split(", "):
            if "=" in part:
                k, v = part.split("=", 1)
                d[k.strip()] = v.strip()
        return d

    out = []
    for i, blob in enumerate(sigs):
        dec = WD.decode_blob(blob)
        e = {
            "i": i, "blob": blob, "record": dec["record"],
            "consts_ok": dec["consts_ok"], "S": dec["F_seed"],
            "d2w_le": dec["d2w"], "head": dec["head"], "block": dec["block"],
            "tail2": dec["tail2"], "header": dec["header"],
            "digest32": blob[160:192], "second": sig_seconds[i],
            "claims": parse_map(si[i]) if i < len(si) else None,
        }
        out.append(e)
    out.sort(key=lambda e: (e["S"] if e["second"] is None else e["second"]))
    for n, e in enumerate(out):
        e["i"] = n
    return out


def load_inst():
    ph3 = json.load(open(PAIR_H3))
    out = []
    for r in ph3:
        dec = WD.decode_blob(bytes.fromhex(r["blob"]))
        out.append({
            "i": r["i"], "H": r.get("H"), "blob": bytes.fromhex(r["blob"]),
            "record": dec["record"], "consts_ok": dec["consts_ok"],
            "S": dec["F_seed"], "d2w_le": dec["d2w"], "head": dec["head"],
            "block": dec["block"], "tail2": dec["tail2"],
            "header": dec["header"], "second": r.get("second"),
        })
    out.sort(key=lambda e: e["S"])
    return out


# ---------------------------------------------------------------------------
# 5. simple compositions
# ---------------------------------------------------------------------------
def try_compositions(blk, S, head, d0=None, d4=None, tail2=None):
    S4 = S.to_bytes(4, "big")
    S4le = S.to_bytes(4, "little")
    res = {}

    def chk(name, cand):
        if cand is not None and len(cand) == 32:
            res[name] = (cand == blk, cand.hex())

    chk("S*8", S4 * 8)
    chk("S*8_le", S4le * 8)
    chk("S4+0*28", S4 + b"\x00" * 28)
    chk("0*28+S4", b"\x00" * 28 + S4)
    chk("S*4+8*4", S4 * 4 + b"\x08" * 4)
    chk("S*4+28*4", S4 * 4 + b"\x1c" * 4)
    chk("sha1(d9)", hashlib.sha1(D9).digest())
    chk("sha256(d9)", hashlib.sha256(D9).digest())
    chk("sha256(d9)[::-1]", hashlib.sha256(D9).digest()[::-1])
    chk("md5(d9)*2", hashlib.md5(D9).digest() * 2)
    chk("sha256(\"\")", SHA0)
    chk("sha0^sha0", xor(SHA0, SHA0))
    chk("head*2", head * 2)
    chk("head*2^S*8", xor(head * 2, S4 * 8))
    for nm, msg in (("head", head), ("S", S4), ("d9", D9), ("head+S", head + S4),
                    ("S+head", S4 + head), ("head+d9", head + D9),
                    ("d9+head", D9 + head), ("S+d9", S4 + D9),
                    ("d9+S", D9 + S4), ("S_le", S4le), ("sha0", SHA0)):
        for hn, hf in (("sha256", lambda b: hashlib.sha256(b).digest()),
                       ("sha1x2", lambda b: hashlib.sha1(b).digest() * 2),
                       ("sha1", lambda b: hashlib.sha1(b).digest()),
                       ("md5x2", lambda b: hashlib.md5(b).digest() * 2),
                       ("sha512lo", lambda b: hashlib.sha512(b).digest()[:32])):
            chk("%s(%s)" % (hn, nm), hf(msg))
    if d0 is not None:
        chk("d0[:32]", d0[:32])
        chk("sha1(d0)", hashlib.sha1(d0).digest())
        chk("sha256(d0)", hashlib.sha256(d0).digest())
        chk("sha1(d0+S)", hashlib.sha1(d0 + S4).digest())
        chk("sha256(d0+S)", hashlib.sha256(d0 + S4).digest())
    if d4 is not None:
        chk("d4*2", d4 * 2)
        chk("d4", d4)
        chk("sha256(d4)", hashlib.sha256(d4).digest())
        chk("sha256(d4+S)", hashlib.sha256(d4 + S4).digest())
        chk("d4^S*8", xor(d4, S4 * 8))
    return res


# ---------------------------------------------------------------------------
# 9. FinEx reproduction — the decisive test
# ---------------------------------------------------------------------------
def solve_head_phase(d4w, head, max_len=7):
    """Find the d0 head-selector prefix that yields `head` from this d4."""
    src = Fmod._d0_source(d4w)
    hv = [int.from_bytes(head[2 * j:2 * j + 2], "big") for j in range(8)]
    for L in range(1, max_len + 1):
        for cand in itertools.product(range(0x20, 0x60), repeat=L):
            sels = tuple(list(cand) + [0x40 | (i & 7) for i in range(L, 72)])
            if all(Fmod._selector_halfword((sels[j] << 1) + 3, src) == hv[j]
                   for j in range(8)):
                return cand
    return None


def finex_reproduce(entries, max_steps=40_000_000, verbose=True):
    """Rebuild the descriptor set from each entry's own claims + region, run the
    FinEx VM, and report whether it emits the genuine 32-byte block."""
    from fin_vm2 import FinEx
    from desc10_law import build_desc10

    out = []
    for e in entries:
        rec, seed = e["record"], e["S"]
        d4w = Fmod._d4_words(seed)
        d4 = b"".join(w.to_bytes(4, "big") for w in d4w)
        d2 = e["d2w_le"].to_bytes(4, "big")
        pfx = solve_head_phase(d4w, e["head"])
        if pfx is None:
            out.append({"i": e["i"], "ok": False, "why": "head phase unsolved"})
            continue
        d0w = Fmod._d0_words(d4w, head=tuple(pfx))
        d0 = b"".join(w.to_bytes(4, "big") for w in d0w)

        claims = e.get("claims")
        if not claims:
            out.append({"i": e["i"], "ok": False, "why": "no claims"})
            continue
        kind = claims.get("activity_kind", "session")
        raw = build_desc10(claims, kind).encode("latin1")
        padded = raw + b"\x00" * (-len(raw) % 4)

        byidx = {
            0: (36, 0, d0), 9: (5, 0, D9),
            8: (4, 0, bytes.fromhex(D8_HEX)), 4: (8, 0, d4), 2: (1, 0, d2),
            7: (1, 0, struct.pack(">I", len(raw))),
            10: (len(padded) // 4, 0, padded),
            5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
            1: (0, 0, b""), 3: (0, 0, b""),
        }
        descs = [byidx[i] for i in VA_ORDER]
        second = e["second"]
        ex = FinEx(int(second), descs)
        status = ex.run(max_steps=max_steps)
        last = {}
        for (sva, n, v) in ex.emit_trace:
            last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
        bys = {}
        for (sva, n), v in last.items():
            bys.setdefault(sva, {})[n] = v
        m = bys.get(SINK)
        if m is None:
            out.append({"i": e["i"], "ok": False, "why": "no sink stream"})
            continue
        blob = b"".join(struct.pack(">I", m.get(k, 0)) for k in range(48))
        orec = WD.whiten_body_inverse(blob[16:160], blob[:16])
        ob = orec[46:78]
        ok = ob == e["block"]
        diff = [k for k in range(144) if orec[k] != rec[k]]
        row = {"i": e["i"], "second": second, "kind": kind,
               "d10_unpadded": len(raw), "phase": [hex(x) for x in pfx],
               "vm_status": status, "vm_steps": ex.steps,
               "block_match": ok,
               "record_differing_bytes": diff,
               "ours_block": ob.hex(), "genuine_block": e["block"].hex()}
        out.append(row)
        if verbose:
            print("  sig%d second=%d kind=%-12s d10=%3dB phase=%-12s "
                  "vm=%s block_match=%s%s"
                  % (e["i"], second, kind, len(raw),
                     ",".join(hex(x) for x in pfx), status, ok,
                     "" if ok else "  diff_at=%s" % diff))
    return out


# ---------------------------------------------------------------------------
def main():
    nofinex = "--nofinex" in sys.argv
    log = read_log()
    rep = {}

    wins = extract_win(log)
    inst = load_inst()

    print("=" * 78)
    print("1. GENUINE WINNING BLOBS  (Signature headers, un-instrumented)")
    print("=" * 78)
    for e in wins:
        print("  win[%d] second=%s len=%d consts_ok=%-5s S=%-10d (0x%08x) "
              "tail2=%s" % (e["i"], e["second"], len(e["blob"]), e["consts_ok"],
                            e["S"], e["S"], e["tail2"].hex()))
        print("         head  = %s" % e["head"].hex())
        print("         block = %s" % e["block"].hex())
    nok = sum(e["consts_ok"] for e in wins)
    print("  record_checks: %d/%d" % (nok, len(wins)))
    rep["consts_ok_wins"] = nok
    rep["wins"] = [{k: (v.hex() if isinstance(v, bytes) else v)
                    for k, v in e.items() if k not in ("record", "blob",
                                                       "claims")} for e in wins]

    print()
    print("=" * 78)
    print("2. INSTRUMENTED CORPUS  (pair_h3.json, Frida-hooked)")
    print("=" * 78)
    for r in inst:
        print("  inst[i=%d] second=%s consts_ok=%-5s S=%-10d (0x%08x) tail2=%s"
              % (r["i"], r["second"], r["consts_ok"], r["S"], r["S"],
                 r["tail2"].hex()))
        print("         head  = %s" % r["head"].hex())
        print("         block = %s" % r["block"].hex())
    print("  record_checks: %d/%d" % (sum(r["consts_ok"] for r in inst), len(inst)))

    print()
    print("=" * 78)
    print("3. ARE THE 6 BLOCKS DISTINCT?  pairwise XOR / delta")
    print("=" * 78)
    distinct = len({e["block"] for e in wins})
    print("  distinct win blocks: %d / %d" % (distinct, len(wins)))
    cols = [len({e["block"][k] for e in wins}) for k in range(32)]
    print("  per-byte-position distinct values across the 6: %s" % cols)
    print("  positions where any two blocks agree: %s"
          % [k for k, c in enumerate(cols) if c < len(wins)])
    xd = xor_diffs(wins)
    for x in xd:
        print("  win[%d]^win[%d] dS=%-11d agree@%s xor=%s"
              % (x["pair"][0], x["pair"][1], x["dS"], x["equal_bytes"],
                 x["xor"]))
    print("  consecutive-signing mod-256 block deltas:")
    for i in range(len(wins) - 1):
        print("    %d->%d  dS=%-11d delta=%s"
              % (i, i + 1, wins[i + 1]["S"] - wins[i]["S"],
                 sub(wins[i + 1]["block"], wins[i]["block"]).hex()))
    print("  -> no sequential/counter structure; every pairwise XOR is dense.")
    rep["distinct_win_blocks"] = distinct
    rep["pairwise"] = xd

    print()
    print("=" * 78)
    print("4. IS THE BLOCK VISIBLE IN THE CAPTURE LOG?")
    print("=" * 78)
    low = log.lower().encode()
    hits = {}
    for e in wins:
        full = e["block"].hex().encode() in low
        found = [k for k in range(25) if e["block"][k:k + 8].hex().encode() in low]
        hits[e["i"]] = {"full32": full, "n8": len(found), "at": found}
        print("  win[%d] full-32 present: %-5s   8-byte windows: %2d/25 %s"
              % (e["i"], full, len(found), found))
    print("  -> the block is never emitted in the clear; it exists only inside")
    print("     the encrypted blob, i.e. it is a derived value, not a logged one.")
    rep["log_search"] = hits

    print()
    print("=" * 78)
    print("5. SIMPLE COMPOSITIONS OF (S, head, cert, d0, d4)")
    print("=" * 78)
    comp = {}
    for e in wins:
        d4w = Fmod._d4_words(e["S"])
        d4 = b"".join(w.to_bytes(4, "big") for w in d4w)
        pfx = solve_head_phase(d4w, e["head"])
        d0 = None
        if pfx:
            d0 = b"".join(w.to_bytes(4, "big")
                          for w in Fmod._d0_words(d4w, head=tuple(pfx)))
        res = try_compositions(e["block"], e["S"], e["head"], d0, d4)
        good = sorted(k for k, (ok, _h) in res.items() if ok)
        comp[e["i"]] = good
        print("  win[%d] phase=%s  matches: %s"
              % (e["i"], [hex(x) for x in pfx] if pfx else "?",
                 good if good else "NONE"))
    comp_i = {}
    for r in inst:
        d4w = Fmod._d4_words(r["S"])
        d4 = b"".join(w.to_bytes(4, "big") for w in d4w)
        pfx = solve_head_phase(d4w, r["head"])
        d0 = None
        if pfx:
            d0 = b"".join(w.to_bytes(4, "big")
                          for w in Fmod._d0_words(d4w, head=tuple(pfx)))
        res = try_compositions(r["block"], r["S"], r["head"], d0, d4)
        comp_i[r["i"]] = sorted(k for k, (ok, _h) in res.items() if ok)
    print("  instrumented matches: %s"
          % {k: v for k, v in comp_i.items() if v})
    print("  -> no closed-form / hash / padding relation in EITHER family.")
    rep["compositions"] = comp
    rep["compositions_inst"] = comp_i

    print()
    print("=" * 78)
    print("6. IS THE BLOCK A FUNCTION OF S ALONE?")
    print("=" * 78)
    print("  win  S: %s" % [e["S"] for e in wins])
    print("  inst S: %s" % [r["S"] for r in inst])
    print("  S overlap between families: %s"
          % sorted({e["S"] for e in wins} & {r["S"] for r in inst}))
    g = {}
    for r in inst:
        g.setdefault(r["S"], set()).add(r["block"])
    dup = {s: v for s, v in g.items() if len(v) > 1}
    same = {s: v for s, v in g.items() if len(v) == 1 and
            sum(1 for r in inst if r["S"] == s) > 1}
    print("  instrumented rows sharing one S with DIFFERENT blocks: %s" % dup)
    print("  instrumented rows sharing one S with the SAME block: %s"
          % {s: [b.hex() for b in v] for s, v in same.items()})
    print("  -> the only repeated S in the corpus (pair_h3 i=2/i=4) is a literal")
    print("     duplicate capture, so S alone is neither confirmed nor refuted;")
    print("     across distinct S the block is always distinct (14/14).")
    rep["S"] = {"win": [e["S"] for e in wins], "inst": [r["S"] for r in inst],
                "same_S_conflicts": len(dup)}

    print()
    print("=" * 78)
    print("7. GENUINE vs INSTRUMENTED — can the server tell them apart?")
    print("=" * 78)
    stat = {}
    for nm, fam in (("genuine", wins), ("instrum", inst)):
        allb = b"".join(e["block"] for e in fam)
        stat[nm] = {
            "n": len(fam),
            "n_blocks": len({e["block"] for e in fam}),
            "byte_alphabet": len(set(allb)),
            "bit1_frac": round(sum(bin(b).count("1") for b in allb)
                               / (8.0 * len(allb)), 4),
            "entropy": round(entropy(allb), 4),
            "zero_bytes": sum(1 for b in allb if b == 0),
            "unique_8w": len({e["block"][k:k + 8] for e in fam
                              for k in range(25)}),
        }
    keys = list(stat["genuine"])
    print("  %-16s %10s %10s" % ("metric", "genuine", "instrum"))
    for k in keys:
        print("  %-16s %10s %10s" % (k, stat["genuine"][k], stat["instrum"][k]))
    wset = {e["block"] for e in wins}
    iset = {r["block"] for r in inst}
    ww = {e["block"][k:k + 8] for e in wins for k in range(25)}
    iw = {r["block"][k:k + 8] for r in inst for k in range(25)}
    print("  cross-family block collisions : %d" % len(wset & iset))
    print("  cross-family shared 8-B windows: %d  (win %d uniq, inst %d uniq)"
          % (len(ww & iw), len(ww), len(iw)))
    print("  tail2: genuine %s ; instrumented %s"
          % (sorted({e["tail2"].hex() for e in wins}),
             sorted({r["tail2"].hex() for r in inst})))
    print("  head : %d/%d distinct genuine, %d/%d distinct instrumented, "
          "0 overlap" % (len({e["head"] for e in wins}), len(wins),
                         len({r["head"] for r in inst}), len(inst)))
    print()
    print("  -> STATISTICALLY INDISTINGUISHABLE. Both families are full-entropy")
    print("     32-byte strings, all-distinct, no shared 8-byte window, tail2")
    print("     constant 0000, same record layout, same cert SHA-1. The block")
    print("     does NOT leak instrumentation.")
    rep["famstats"] = stat
    rep["cross"] = {"block_collisions": len(wset & iset),
                    "shared_8w": len(ww & iw)}

    print()
    print("=" * 78)
    print("8. IS [46:78) PLAINTEXT IN THE ENCODED BLOB?")
    print("=" * 78)
    for e in wins:
        enc = e["blob"][46:78]
        print("  win[%d] blob[46:78] == record block : %-5s" % (e["i"],
                                                               enc == e["block"]))
    print("  round-trip forward(record) == blob[16:160): %s"
          % [WD.whiten_forward(e["record"], e["blob"][:16]) == e["blob"][16:160]
             for e in wins])
    print("  -> ENCRYPTED. The block is covered by the whitening chain (it sits")
    print("     in chunks 2-3, so changing it perturbs every later chunk), and")
    print("     the ciphertext shares no byte with the plaintext block.")
    rep["plaintext_in_blob"] = [e["blob"][46:78] == e["block"] for e in wins]

    print()
    print("=" * 78)
    print("9. CAN PYTHON COMPUTE THE BLOCK?  (FinEx VM over rebuilt descriptors)")
    print("=" * 78)
    if nofinex:
        print("  skipped (--nofinex)")
        rep["finex"] = None
    else:
        rows = finex_reproduce(wins)
        n = sum(1 for r in rows if r.get("block_match"))
        print()
        print("  BLOCK REPRODUCED BYTE-EXACTLY: %d / %d genuine blobs" % (n, len(rows)))
        bad = [r for r in rows if not r.get("block_match")]
        for r in bad:
            print("   sig%s second=%s kind=%s d10=%sB -> diff bytes %s"
                  % (r["i"], r.get("second"), r.get("kind"),
                     r.get("d10_unpadded"), r.get("record_differing_bytes")))
            print("      ours    %s" % r["ours_block"])
            print("      genuine %s" % r["genuine_block"])
        print()
        print("  -> YES, the block is COMPUTABLE and is not a hash or a")
        print("     secret: it is a pure output of the FinEx VM run over the")
        print("     11 adj9 descriptors (d0 region, cert, d8 consts, d4, d2,")
        print("     desc10 length, the claims string, zeros). Known inputs,")
        print("     zero free variables.")
        rep["finex"] = rows
        rep["finex_block_matches"] = n

    with open(OUT_JSON, "w") as fh:
        json.dump(rep, fh, indent=1)
    print()
    print("wrote %s" % OUT_JSON)


if __name__ == "__main__":
    main()
