"""_sub_core_kbhunt.py — locate KB (240 B round-key schedule) inside the
iOS core (and Android control) using storage laws beyond contiguous bytes:

  1. movz-subsequence: KB bytes appear as 16-bit MOVZ immediates (any Rd,
     interleaved with other instructions) — the Android PUSH-block law.
  2. dword immediates: KB words (BE dwords) as movz/movk pairs, plain /
     XOR-0xCC / XOR-0xAA.
  3. single-byte XOR mask over the raw file (any mask 0..255).
  4. halfword-table: KB stored as LE16 halfwords (byte, x, byte, x ...).
  5. dword-table raw BE/LE in data sections.

Run:  python _sub_core_kbhunt.py
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_signer as sg
import _sub_core_macho as macho
from _sub_core_constscan import arm64_dword_imm_stream

D = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins"
AND_SO = os.path.join(D, "extracted/aar/jni/arm64-v8a/libsigner.so")
IOS_DEV = os.path.join(D, "extracted/xcframework_dyn/AdjustSigSdk.xcframework/"
                          "ios-arm64/AdjustSigSdk.framework/AdjustSigSdk")

KB = sg.KB  # 240 B


def words(data):
    n = len(data) // 4
    return struct.unpack_from("<%dI" % n, data, 0)


def movz_subsequence(data, target, max_gap=6):
    """Find target bytes (in order) as MOVZ hw=0 immediates with gaps
    <= max_gap instructions.  Returns (start_pos, end_pos, n_matched) of the
    longest match starting at target[0], scanning all start offsets."""
    seq = []
    for i, w in enumerate(words(data)):
        if (w & 0x7F800000) == 0x52800000 and ((w >> 21) & 3) == 0:
            imm = (w >> 5) & 0xFFFF
            if imm <= 0xFF:
                seq.append((i, imm))
    best = None
    # DP: for each seq element, try to extend along target
    m = len(seq)
    from collections import defaultdict
    idx = defaultdict(list)
    for j, (i, imm) in enumerate(seq):
        idx[imm].append(j)
    # chain: for each occurrence of target[0], walk
    from collections import defaultdict
    nxt = defaultdict(list)          # pos_in_seq -> list of (matched_len, j_next)
    for j0 in idx[target[0]]:
        ln, cur, last_i = 1, j0, seq[j0][0]
        while ln < len(target):
            nb = target[ln]
            cand = [j for j in idx[nb] if j > cur and seq[j][0] - last_i <= max_gap]
            if not cand:
                break
            jn = cand[0]
            ln += 1
            cur = jn
            last_i = seq[jn][0]
        if best is None or ln > best[2]:
            best = (seq[j0][0], last_i, ln)
        if ln == len(target):
            break
    return best


def kb_dword_imm(data, mask=None):
    """Search KB's 60 BE dwords in the movz/movk immediate stream (masked)."""
    dw = [struct.unpack(">I", KB[i:i + 4])[0] for i in range(0, 240, 4)]
    want = {}
    for k, w in enumerate(dw):
        want[w] = k
        if mask:
            want[w ^ mask] = k
    hits = {}
    for pos, val, _rd in arm64_dword_imm_stream(data):
        if val in want:
            hits.setdefault(want[val], []).append(pos)
    return hits


def xor_mask_scan(data, pat, masks=range(256)):
    out = {}
    for m in masks:
        p = bytes(b ^ m for b in pat)
        i = data.find(p)
        if i != -1:
            out[m] = i
    return out


def halfword_table(data, n=32):
    """KB[i] stored as LE16 at stride 2 (byte, filler)."""
    pat = struct.pack("<%dH" % n, *KB[:n])
    return raw_all(data, pat)


def raw_all(data, pat, limit=4):
    out, i = [], data.find(pat)
    while i != -1 and len(out) < limit:
        out.append(i)
        i = data.find(pat, i + 1)
    return out


def main():
    targets = []
    with open(AND_SO, "rb") as f:
        targets.append(("android-arm64 (control)", f.read()))
    sl = macho.slices(IOS_DEV)[0]
    targets.append(("ios-device-arm64", sl.data))

    out = {}
    for name, data in targets:
        r = {}
        r["movz_subsequence(KB[:64])"] = movz_subsequence(data, KB[:64])[:3] \
            if False else movz_subsequence(data, KB[:64])
        r["movz_subsequence(KB[128:192])"] = movz_subsequence(data, KB[128:192])
        r["dword_imm_plain"] = {k: v[:2] for k, v in kb_dword_imm(data).items()}
        r["dword_imm_xorCC"] = {k: v[:2] for k, v in kb_dword_imm(data, 0xCCCCCCCC).items()}
        r["dword_imm_xorAA"] = {k: v[:2] for k, v in kb_dword_imm(data, 0xAAAAAAAA).items()}
        r["xor_mask(KB[:16])"] = xor_mask_scan(data, KB[:16])
        r["halfword_le16(KB[:32])"] = halfword_table(data)
        r["raw_dword_be(KB[:16])"] = raw_all(data, struct.pack(">4I",
            *[struct.unpack(">I", KB[i:i+4])[0] for i in range(0, 16, 4)]))
        out[name] = r
        print(f"\n===== {name} =====")
        for k, v in r.items():
            print(f"  {k}: {v}")
    with open(os.path.join(HERE, "_sub_core_kbhunt_out.json"), "w") as f:
        json.dump(out, f, indent=1, default=str)
    print("\nwrote _sub_core_kbhunt_out.json")


if __name__ == "__main__":
    main()
