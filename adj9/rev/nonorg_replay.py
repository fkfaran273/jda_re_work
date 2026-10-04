r"""nonorg_replay.py — the test the user asked for, on the ONLY genuine
non-organic install in the corpus.

Take the genuine non-organic session/click/attribution from
`rev/_saz_x/raw/{1,2,3}_c.txt` (GAID d016e7e4, tracker 24pxw9rl / VKM Digital
Yeni) and re-sign the IDENTICAL wire params with OUR signer, then diff all 192
bytes against the genuine signature.

Two things are being tested, and they are different:
  1. CLAIMS  — does our desc10 claim law produce the same claim string the
     device signed?  If not, our signature is missing something, full stop.
  2. REGION  — given the right claims, can our region/VM reproduce the bytes?
     (Known limit: the d0 head is a per-call channel we cannot compute.)

Step 1 is the important one and needs no VM run: decode the genuine d10 by
inverting the emitter is hard, so instead we MINT at the genuine signing
second and compare the recovered descriptor content.  We recover the signing
second by inverting the 16-byte Random3 header (blob[:16] == make_header(sec)).
"""
from __future__ import annotations
import base64, json, os, re, struct, sys, urllib.parse
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M
import F as Fmod
import adj9_full_chain as fc

SAZ = os.path.join(HERE, "_saz_x", "raw")
OUT = os.path.join(HERE, "nonorg_replay_result.json")


def find_second(blob_hex32, lo, hi):
    """Invert the 16-byte Random3 header: blob[:16] == make_header(second).

    `blob_hex32` must be the hex of the FIRST 16 BYTES (32 hex chars).
    """
    for s in range(lo, hi):
        if M.make_header(s).hex() == blob_hex32:
            return s
    return None


def parse(path):
    t = open(path, encoding="utf-8", errors="replace").read()
    sig = re.search(r'signature="([A-Za-z0-9+/=]+)"', t)
    body = t.split("\n\n", 1)[1] if "\n\n" in t else ""
    params = dict(urllib.parse.parse_qsl(body.strip(), keep_blank_values=True))
    line1 = t.split("\n")[0]
    kind = ("session" if "/session" in line1 else
            "click" if "/sdk_click" in line1 else "attribution")
    return kind, params, base64.b64decode(sig.group(1))


def build_claims(params, kind):
    """Our law's claim map, from the genuine wire params."""
    return M.claims_from_wire(params, kind)


def main():
    rows = []
    for fn, lo, hi in (("1_c.txt", 1789388585, 1789388592),
                       ("2_c.txt", 1789388585, 1789388592),
                       ("3_c.txt", 1789388585, 1789388592)):
        path = os.path.join(SAZ, fn)
        kind, params, blob = parse(path)
        rec = {"file": fn, "kind": kind, "n_wire": len(params),
               "blob": blob.hex(), "blob_len": len(blob)}
        sec = find_second(blob[:16].hex(), lo, hi)
        rec["second"] = sec
        if sec is None:
            rec["error"] = ("signing second not found in window; header law "
                            "or window wrong")
            rows.append(rec)
            print("=== %s %s: second NOT FOUND ===" % (fn, kind), flush=True)
            continue
        print("=== %s %s  second=%d  wire=%d ===" % (fn, kind, sec,
                                                     len(params)), flush=True)
        # our claim string for the genuine params
        try:
            claims = build_claims(params, kind)
        except Exception as e:
            rec["claims_error"] = repr(e)
            rows.append(rec)
            print("   claims_from_wire FAILED: %r" % (e,), flush=True)
            continue
        padded, unpadded = M.claims_for_law(claims, kind)
        rec["our_claims"] = len(claims)
        rec["our_desc10_len"] = len(padded)
        rec["our_unpadded"] = unpadded
        rec["our_desc10"] = padded.decode("latin1")
        # mint at the genuine second
        d0w, d2w, d4w = Fmod.region(sec, M.DEFAULT_PID, 0, head=Fmod.HEAD_FIRST)
        by = {0: (36, 0, b"".join(struct.pack(">I", w) for w in d0w)),
              9: (5, 0, bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")),
              8: (4, 0, bytes.fromhex("bffffffffffffd1f0007000000000000")),
              4: (8, 0, b"".join(struct.pack(">I", w) for w in d4w)),
              2: (1, 0, struct.pack(">I", d2w)),
              7: (1, 0, struct.pack(">I", unpadded)),
              10: (len(padded) // 4, 0, padded),
              5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
              1: (0, 0, b""), 3: (0, 0, b"")}
        ours, vm = M.finex_mint([by[i] for i in M.VA_ORDER], sec)
        rec["our_blob"] = ours.hex()
        rec["vm_status"] = vm.get("status")
        rec["byte_identical"] = (ours == blob)
        same = sum(1 for a, b in zip(ours, blob) if a == b)
        rec["bytes_matching"] = same
        rec["first_diff"] = next((i for i, (a, b) in enumerate(zip(ours, blob))
                                  if a != b), None)
        print("   claims=%d  desc10=%dB  status=%s" % (
            len(claims), len(padded), vm.get("status")))
        print("   BYTE-IDENTICAL: %s   (%d/192 bytes match, first diff @%s)"
              % (ours == blob, same, rec["first_diff"]), flush=True)
        if rec["first_diff"] is not None:
            i = rec["first_diff"]
            print("   genuine: %s" % blob[i:i+16].hex())
            print("   ours   : %s" % ours[i:i+16].hex())
        rows.append(rec)
        json.dump(rows, open(OUT, "w"), indent=1)

    json.dump(rows, open(OUT, "w"), indent=1)
    print("\n=== SUMMARY: replay of the ONLY genuine non-organic record ===")
    for r in rows:
        if "error" in r:
            print("  %s %-12s %s" % (r["file"], r["kind"], r["error"]))
        else:
            print("  %s %-12s identical=%-5s %d/192  claims=%s d10=%sB"
                  % (r["file"], r["kind"], r["byte_identical"],
                     r["bytes_matching"], r.get("our_claims"),
                     r.get("our_desc10_len")))
    print("saved", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
