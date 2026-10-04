"""test_h_swap.py — local experiment: replace the TEE-HMAC H with a random
32-byte value (known length) and regenerate the signature with the proven
VM simulator. Demonstrates the model's prediction: H is opaque input, so
the body regenerates self-consistently.

Control: reproduce the captured signing byte-exact (48/48).
Test: 10 variants with random H' -> 10 candidate signatures.

This script does NOT send anything anywhere. It only produces local test
vectors (h_swap_results.json) for inspection. Submitting to a third-party
API is a separate decision outside this tool.
"""
import json
import struct
import sys
import os
import secrets

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import Random3

D = json.load(open(os.path.join(HERE, "fin_descs.json")))
SEED = D["target"]["second"]
BLOB = bytes.fromhex(D["target"]["blob_hex"])
# va_order: [#0,#9,#8,#4,#2,#7,#10,#5,#1,#6,#3] -> H is the 4th entry
H_SLOT = [i for i, d in enumerate(D["descs"]) if d["len_dw"] == 8][0]


def build_descs(h_bytes=None):
    descs = []
    for d in D["descs"]:
        data = bytes.fromhex(d["data_hex"])
        if h_bytes is not None and d["len_dw"] == 8:
            data = h_bytes
        descs.append((d["len_dw"], 0, data))
    return descs


def make_signature(descs):
    """run the VM forward, return the 48-dword output window as bytes."""
    ex = FinEx(SEED, descs)
    status = ex.run(max_steps=12_000_000)
    # output stream = slot-0 field sink (F0), last-write-wins window [0..48)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    F0 = None
    for (s, n) in out:
        # the blob slot stream: find the stream whose window matches native
        cand = tuple(out.get((s, k), 0) for k in range(4))
        hdr = struct.unpack(">4I", BLOB[:16])
        if cand == hdr and all(
                out.get((s, k), 0) == struct.unpack_from(">I", BLOB, 4 * k)[0]
                for k in range(4, 8)):
            F0 = s
            break
    if F0 is None:
        return status, None, ex
    sig = b"".join(struct.pack(">I", out.get((F0, k), 0)) for k in range(48))
    return status, sig, ex


def main():
    print("=" * 70)
    print("CONTROL: reproduce the captured signing (H real, captured inputs)")
    st, sig, _ = make_signature(build_descs())
    print("  status=%s  match vs blob: %d/48 dwords" % (
        st, sum(1 for a, b in zip(struct.unpack(">48I", sig or b"\0" * 192),
                                  struct.unpack(">48I", BLOB)) if a == b)))
    if sig == BLOB:
        print("  BYTE-EXACT (48/48) — control OK")
    else:
        print("  control mismatch — aborting")
        return

    print("\nTEST: random H' (32 B) x 10")
    results = []
    for k in range(10):
        h_rand = secrets.token_bytes(32)
        st, sig, _ = make_signature(build_descs(h_rand))
        if sig is None:
            print("  variant %d: simulator diverged (status=%s)" % (k, st))
            continue
        diffs = sum(1 for a, b in zip(sig, BLOB) if a != b)
        hdr = struct.unpack(">4I", sig[:16])
        results.append({
            "variant": k, "h_random": h_rand.hex(),
            "signature_hex": sig.hex(),
            "header_hex": hdr[0:4] and bytes(sig[:16]).hex(),
            "body_diff_vs_original_bytes": diffs,
        })
        print("  variant %d: header=%s…  body differs in %d/192 bytes" % (
            k, sig[:8].hex(), diffs))

    out = os.path.join(HERE, "h_swap_results.json")
    json.dump(results, open(out, "w"), indent=1)
    print("\nsaved %s (%d candidate signatures)" % (out, len(results)))
    print("\nNote on the model:")
    print("  H is 8 opaque dwords to the VM. With a random H' every dword")
    print("  from that point on changes (total diffusion) — each variant is a")
    print("  self-consistent signature for the SAME request, as predicted.")
    print("  The server-side question (does Adjust accept a body whose H slot")
    print("  holds a non-TEE value?) is an experiment against THEIR API, not")
    print("  ours — and is deliberately not included here.")


if __name__ == "__main__":
    main()
