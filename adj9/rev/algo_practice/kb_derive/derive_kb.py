"""derive_kb.py — standalone, stdlib-only regeneration of KB (240 B).

FINDING (proven by memory-write provenance tracing of the FinEx VM, see
KB_DERIVED.md): KB is NOT computed at runtime.  The VM program carries the
240 round-key bytes as LITERAL immediates in an unrolled PUSH block:

    0x119bb8  mov w2, #0x43      ; KB[0]
    0x119bbc  bl  0x147630       ; OP_PUSH (queue)
    0x119bd0  mov w2, #0x101     ; offset n = 257 (emit base + n = slot 949)
    0x119bd4  bl  0x147630
    ...                          ; per byte: push value, push offset, stride 0x18
    0x11c8bc  bl  0x147630       ; last push: 0xf0 = 240 = pair count
    0x11c8d0  bl  0x147734       ; POP count
    0x11c8ec  bl  0x146558       ; MKITER(240)
    0x11c8f8..0x11c94c          ; loop: POP n, POP v, EMIT(stream, n, v), ITERNEXT

The queue is LIFO, so the ascending-index pushes pop in descending index
order and the block emits KB[239]..KB[0] into scratch RAM (stream
0x5450001000, slots 949..1188 during a signing).  The whitening cipher then
reads the schedule byte-per-byte via lenq (pc 0x111afc, 9 chunks x 240 B).

Because each byte is a 16-bit MOVZ immediate, KB never appears as 16
contiguous bytes in libsigner.so — which is why the rodata scan missed it.

derive_kb() re-derives KB from the embedded program image (signer_simple.py's
_LIB_SPANS, which mirror libsigner.so's code) with no hardcoded key bytes:
it scans for the 481-site run of (mov w2,#imm ; bl OP_PUSH) pairs and takes
the value immediates.  Self-validating gates, no VM execution needed.
"""
import ast
import base64
import os
import re
import struct

SIGNER_SIMPLE = os.environ.get(
    "SIGNER_SIMPLE",
    "C:/Users/Apps/Downloads/com.penti.app/adj9sign/signer_simple.py")

OP_PUSH = 0x147630          # queue push thunk targeted by every literal push
N_SITES = 481               # 240 (value, offset) pairs + final count 240


def _load_spans(path=SIGNER_SIMPLE):
    """Return [(start_va, end_va, bytes)] parsed from signer_simple.py.
    stdlib only: regex + ast.literal_eval + base64."""
    src = open(path, "r", encoding="utf-8").read()
    m = re.search(r"_LIB_SPANS = (\[.*?\n\])", src, re.S)
    if not m:
        raise RuntimeError("_LIB_SPANS not found in " + path)
    spans = ast.literal_eval(m.group(1))
    return [(a, b, base64.b64decode(s)) for (a, b, s) in spans]


def _push_sites(spans):
    """Yield (pc, imm) for every `mov w2,#imm ; bl OP_PUSH` site, in
    program order.  Accepts MOVZ w2 imm16 (hw=0) and the `mov w2, wzr`
    zero-encoding (ORR w2,wzr,wzr = 0x2A1F03E2) used for KB[13]=0x00."""
    for a, b, raw in sorted(spans):
        for off in range(0, len(raw) - 7, 4):
            w = struct.unpack_from("<I", raw, off)[0]
            # movz/mov w2, #imm  (32-bit, hw==0, Rd==2)
            if (w & 0x7F800000) == 0x52800000 and (w >> 21 & 3) == 0 \
                    and (w & 0x1F) == 2:
                imm = (w >> 5) & 0xFFFF
            elif w == 0x2A1F03E2:            # mov w2, wzr  ->  0
                imm = 0
            else:
                continue
            wb = struct.unpack_from("<I", raw, off + 4)[0]
            if (wb & 0xFC000000) != 0x94000000:
                continue                     # not bl
            disp = wb & 0x03FFFFFF
            if disp & 0x02000000:
                disp -= 0x04000000           # sign-extend imm26
            if a + off + 4 + (disp << 2) != OP_PUSH:
                continue                     # bl not targeting OP_PUSH
            yield a + off, imm


def derive_kb(path=SIGNER_SIMPLE):
    """Regenerate the 240-byte key schedule KB byte-exact.  Returns bytes."""
    sites = list(_push_sites(_load_spans(path)))
    # contiguous unrolled runs: consecutive sites at stride 0x18
    runs, cur = [], [sites[0]]
    for prev, site in zip(sites, sites[1:]):
        if site[0] - prev[0] == 0x18:
            cur.append(site)
        else:
            runs.append(cur)
            cur = [site]
    runs.append(cur)
    for run in runs:
        if len(run) != N_SITES:
            continue
        imms = [imm for _, imm in run]
        if imms[-1] != 240:                  # the MKITER pair count
            continue
        offs = imms[1:-1:2]                  # slot offsets 257..496
        if offs != list(range(offs[0], offs[0] + 240)):
            continue
        vals = imms[:-1:2]                   # KB[0..239] ascending
        return bytes(vals)
    raise RuntimeError("KB push-block not found (%d sites scanned)"
                       % len(sites))


if __name__ == "__main__":
    kb = derive_kb()
    print("derive_kb():", kb[:16].hex(), "...", kb[-16:].hex())
    sys_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "pure_signer")
    sys_path = os.path.normpath(sys_path)
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "pure_sign", os.path.join(sys_path, "pure_sign.py"))
    ps = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ps)
    ok = kb == ps.KB
    print("vs pure_sign.KB:", "MATCH 240/240" if ok else "MISMATCH")
    print("hex:", kb.hex())
