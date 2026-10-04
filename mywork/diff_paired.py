"""diff_paired.py — byte-diff: device libsigner output vs the offline signer.

Input : artifacts/paired_mint.json   (written by paired_mint.py)
        * map          - the exact wire map handed to the device signer
        * blob_hex     - the device's 192-byte blob (server-visible bytes)
        * paired_row   - the device descriptor plane, captured in-process by
                         foldhook_native.js: second, S, head[], and
                         desc[did] = {w0, lenDwords, length, hex}
                         (hex = the raw descriptor bytes as the native holds
                         them, so it is directly comparable to _b(words))

Each check prints its own verdict line:

  P0  seed/d2 law     d2 descriptor == LE store of S read back BE
  P1  header law      blob[:16] == make_header(second)
  P2  VM replay       FinEx(second, CAPTURED descs) == blob   (48/48 dwords)
  P3  descriptor #10  build_desc10(claims_from_wire(map)) == captured #10
  P4  region lift     adj9_signer.region(seed=S, head) == captured #0/#2/#4
                      and F.region(V=?, pid=?) for the seed inversion
  P5  end-to-end      mint_blob(claims, second, seed=S, head=captured)
  P6  head sequence   captured 0x1441e4 w1 list vs F/adjs head tables

P2 isolates the VM/serializer plane from the input plane: if P2 is byte-exact
then every divergence below is an INPUT-PLANE problem (claims/region/head),
not a VM problem.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
SIGNER = os.path.join(HERE, "signer")
sys.path.insert(0, SIGNER)
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")

import F as Fmod                                        # noqa: E402
import adj9_signer as S                                 # noqa: E402
from desc10_law import build_desc10                    # noqa: E402
from fin_vm2 import FinEx                              # noqa: E402
from header_gen import make_header                     # noqa: E402

VA_ORDER = S.VA_ORDER                                  # [0,9,8,4,2,7,10,5,1,6,3]
BLOB_WORDS = S.BLOB_WORDS                              # 48
IN = os.path.join(HERE, "artifacts", "paired_mint.json")
if len(sys.argv) > 1:                                  # override for self-tests
    IN = sys.argv[1]

PASS, FAIL = "PASS", "FAIL"
_verdicts = []


def verdict(tag, ok, detail=""):
    _verdicts.append((tag, bool(ok)))
    return "%-4s %s" % (tag, PASS if ok else FAIL) + (("  " + detail) if detail else "")


def words_be(ws):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in ws)


def desc_bytes(row, did):
    """Raw bytes of captured descriptor `did`, or None if the slot was never
    recorded.  A descriptor that EXISTS with length 0 yields b"" -- that is a
    real, expected case (descriptors #1 and #3 are empty), not a gap."""
    d = (row.get("desc") or {}).get(str(did))
    if d is None:
        return None
    hx = d.get("hex")
    if hx is None or str(hx).startswith("ERR"):
        return None
    return bytes.fromhex(hx)


def descs_from_row(row):
    """Captured device plane -> the [(len_dw, tag, data)] tuples FinEx wants."""
    out, missing = [], []
    for did in VA_ORDER:
        raw = desc_bytes(row, did)
        d = (row.get("desc") or {}).get(str(did)) or {}
        if raw is None:
            missing.append(did)
            continue
        padded = raw + b"\x00" * (-len(raw) % 4)
        # native: len = 4*(w0>>>2) + (w0&3); FinEx takes the dword count
        w0 = int(d.get("w0", 0))
        n = max(w0 >> 2, len(padded) // 4)
        out.append((n, 0, padded))
    return out, missing


def run_finex(second, descs, target_words, max_steps=40_000_000):
    """Replay descs through the VM; return (status, best_match, total, diff_idx)."""
    ex = FinEx(int(second), descs)
    status = ex.run(max_steps=max_steps)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = defaultdict(dict)
    for (sva, n), v in last.items():
        bys[sva][n] = v
    tgt = list(target_words)
    # the blob stream is the one carrying the expected header
    hdr = struct.unpack(">4I", make_header(second))
    stream = None
    for sva, m in bys.items():
        if tuple(m.get(k, 0) for k in range(4)) == hdr:
            stream = sva
            break
    if stream is None:
        best, bs = -1, None
        for sva, m in bys.items():
            c = sum(1 for j, v in enumerate(tgt) if m.get(j) == v)
            if c > best:
                best, bs = c, sva
    else:
        best = sum(1 for j, v in enumerate(tgt) if bys[stream].get(j) == v)
        bs = stream
    m = bys.get(bs, {})
    diff = [j for j in range(len(tgt)) if m.get(j) != tgt[j]]
    return status, best, len(tgt), diff, bs, m


def main():
    if not os.path.exists(IN):
        print("missing %s — run paired_mint.py first" % IN)
        return 2
    d = json.load(open(IN, encoding="utf-8"))
    row = d.get("paired_row")
    blob = bytes.fromhex(d["blob_hex"]) if d.get("blob_hex") else b""
    if not row or not blob:
        print("incomplete capture: paired_row=%s blob=%dB"
              % (bool(row), len(blob)))
        return 2

    sec = int(row["second"])
    seed = int(row["S"])
    kind = d["kind"]
    wire = dict(d["map"])
    head_cap = tuple(h.get("w1") for h in (row.get("head") or []))

    print("=" * 72)
    print("PAIRED DIFF  kind=%s sdk=%s second=%d seed=0x%08x" %
          (kind, d.get("sdk"), sec, seed))
    print("  blob=%dB  captured head=%s" %
          (len(blob), " ".join("%02x" % h for h in head_cap)))
    print("=" * 72)

    tgt = list(struct.unpack(">%dI" % (len(blob) // 4), blob))

    # ---- P0  seed / descriptor #2 law ---------------------------------
    cap2 = desc_bytes(row, 2) or b""
    d2_from_S = int.from_bytes((seed & 0xFFFFFFFF).to_bytes(4, "little"), "big")
    print(verdict("P0", cap2 == struct.pack(">I", d2_from_S),
                  "d2=%s expected=%08x" % (cap2.hex() or "-", d2_from_S)))

    # ---- P1  header law -----------------------------------------------
    print(verdict("P1", blob[:16] == make_header(sec),
                  "hdr=%s" % blob[:16].hex()))

    # ---- P2  VM replay from the CAPTURED descriptor plane --------------
    descs, missing = descs_from_row(row)
    if missing:
        print(verdict("P2", False, "capture incomplete, missing %s" % missing))
    else:
        st, best, tot, diff, stream, m = run_finex(sec, descs, tgt)
        print(verdict("P2", best == tot,
                      "status=%s stream=%s match=%d/%d diff=%s"
                      % (st, hex(stream) if stream else None, best, tot,
                         diff[:12])))
        if best != tot and diff:
            j = diff[0]
            print("     first divergent dword %d (byte %d):"
                  " vm=%08x blob=%08x" %
                  (j, j * 4, m.get(j, 0), tgt[j]))

    # ---- P3  descriptor #10 (the claim plane) -------------------------
    try:
        val = S.claims_from_wire(wire, kind)
        law = build_desc10(val, kind).encode("latin1")
    except Exception as e:
        law, val = None, None
        print(verdict("P3", False, "claims_from_wire/build_desc10: %s" % e))
    if law is not None:
        cap10 = desc_bytes(row, 10) or b""
        cap10u = cap10.rstrip(b"\x00")
        ok = (law == cap10u)
        print(verdict("P3", ok,
                      "law=%dB cap=%dB(unpadded %dB)" %
                      (len(law), len(cap10), len(cap10u))))
        if not ok:
            n = min(len(law), len(cap10u))
            i = next((k for k in range(n) if law[k] != cap10u[k]), n)
            print("     first divergent byte @%d" % i)
            print("     law: %r" % law[max(0, i - 24):i + 60])
            print("     cap: %r" % cap10u[max(0, i - 24):i + 60])


    # ---- P4  region lift: does the seed reproduce d0/#2/#4? -----------
    # adj9_signer.region(seed, head) is the signer the A/B used; F.region
    # takes (V, pid) and folds pid into the seed, so invert it.
    cap0, cap4 = desc_bytes(row, 0), desc_bytes(row, 4)
    # adj9_signer.region() runs the REAL native signer under Unicorn and IGNORES
    # head (documented at adj9_signer.region).  Run it ONCE — it is the only
    # test of the actual d0 model that ships, and it costs one emulation.
    t0 = time.time()
    try:
        d0w, d2v, d4w = S.region(seed)
        print(verdict("P4a", words_be(d0w) == cap0 and words_be([d2v]) == cap2
                      and words_be(d4w) == cap4,
                      "adjs.region(seed=%08x) head-ignored  d0=%s d2=%s d4=%s"
                      "[%.1fs]" % (seed,
                                   words_be(d0w) == cap0, words_be([d2v]) == cap2,
                                   words_be(d4w) == cap4, time.time() - t0)))
    except Exception as e:
        print(verdict("P4a", False, "adjs.region threw: %s" % str(e)[:160]))
    # F.region is the pure-Python model; sweep every plausible head cheaply.
    best_f = None
    for hname, h in (("cap", head_cap), ("None", None),
                     ("F.HEAD_FIRST", Fmod.HEAD_FIRST),
                     ("F.HEAD_RESIGN", Fmod.HEAD_RESIGN),
                     ("kind", S.head_for_kind(kind))):
        try:
            d0w, d2v, d4w = Fmod.region(seed, 0, 0, h)
        except Exception as e:
            print("     F.region/%s threw: %s" % (hname, str(e)[:80]))
            continue
        m0 = (words_be(d0w) == cap0) if cap0 else None
        m4 = (words_be(d4w) == cap4) if cap4 else None
        print("     F.region    head=%-13s d0=%s d4=%s"
              % (hname, "EXACT" if m0 else "diff", "EXACT" if m4 else "diff"))
        if m0 and best_f is None:
            best_f = hname
    print(verdict("P4b", best_f is not None,
                  "F.region seed lift: %s" % (best_f or "no head reproduces d0")))

    # ---- P5  full offline mint pinned to the captured second+seed ------
    if val is not None:
        try:
            py_blob, info = S.mint_blob(val, kind, second=sec, seed=seed,
                                        head=head_cap or None)
        except Exception as e:
            py_blob, info = None, {"error": str(e)}
        if py_blob is None:
            print(verdict("P5", False, "mint_blob raised: %s"
                          % str(info.get("error"))[:160]))
        else:
            pw = list(struct.unpack(">%dI" % (len(py_blob) // 4), py_blob))
            pdiff = [j for j in range(min(len(pw), len(tgt))) if pw[j] != tgt[j]]
            print(verdict("P5", not pdiff,
                          "match=%d/%d diff=%s" %
                          (len(pw) - len(pdiff), len(tgt), pdiff[:12])))
            print("     info: %s" % json.dumps(info)[:200])
            if pdiff:
                j = pdiff[0]
                print("     first divergent dword %d (byte %d):"
                      " py=%08x dev=%08x" % (j, j * 4, pw[j], tgt[j]))

    # ---- P6  head sequence -------------------------------------------
    print(verdict("P6", tuple(head_cap) == tuple(S.head_for_kind(kind)),
                  "captured=%s expected=%s" %
                  (" ".join("%02x" % h for h in head_cap),
                   " ".join("%02x" % h for h in S.head_for_kind(kind)))))

    # ---- summary ------------------------------------------------------
    bad = [t for (t, ok) in _verdicts if not ok]
    print("=" * 72)
    print("SUMMARY: %d/%d pass%s" %
          (len(_verdicts) - len(bad), len(_verdicts),
           ("   FAILED: " + " ".join(bad)) if bad else "   ALL EXACT"))
    print("=" * 72)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

