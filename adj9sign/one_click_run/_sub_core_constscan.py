"""_sub_core_constscan.py — byte/immediate search of the Android-proven
adj9 constants inside the Android .so (positive control) and the iOS cores.

Constants source: adj9_signer.py (one_click_run), the byte-exact Android law.
Known Android storage law (from the FinEx VM reversal, hunt_iv2k.py /
derive_kb.py):
  * KB   (240 B round keys) -> 481 unrolled `mov w2,#imm; bl OP_PUSH` sites,
          NEVER contiguous in the file
  * IV2  (32 B block-hash IV) -> 8 dwords as movz/movk immediates,
          each XOR 0xCCCCCCCC
  * DK   (32 B digest MAC key) -> 8 dwords as movz/movk immediates, PLAIN
  * SHA-256 IV  -> dwords XOR 0xCCCCCCCC (anchor)
  * SHA-256 K64 -> dwords XOR 0xAAAAAAAA (anchor)
  * AES S-box -> GENERATED at runtime (must NOT be a table)

For each target binary we therefore scan:
  A. RAW byte patterns (contiguous)
  B. RAW dword patterns (LE 4-byte) - catches literal pools + x86 immediates
  C. ARM64 movz/movk immediate streams (dword reconstruction, plain and
     XOR-0xCC / XOR-0xAA masked) - catches the Android-style storage
Output: JSON to _sub_core_constscan_out.json + console table.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_signer as sg          # the Android-proven law (constants only)
import _sub_core_macho as macho

D = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins"
AND_SO = os.path.join(D, "extracted/aar/jni/arm64-v8a/libsigner.so")
IOS_DEV = os.path.join(D, "extracted/xcframework_dyn/AdjustSigSdk.xcframework/"
                          "ios-arm64/AdjustSigSdk.framework/AdjustSigSdk")
IOS_SIM = os.path.join(D, "extracted/xcframework_dyn/AdjustSigSdk.xcframework/"
                          "ios-arm64_x86_64-simulator/AdjustSigSdk.framework/AdjustSigSdk")
IOS_STATIC_A = os.path.join(D, "extracted/static_a/AdjustSigSdk.a")

KB = sg.KB          # 240 B
IV2 = sg.IV2        # 32 B
DK = sg.DK          # 32 B

# standard SHA-256 IV and K (FIPS anchors)
SHA256_IV = struct.pack(">8I", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
SHA256_K0 = struct.pack(">4I", 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)
# AES S-box first 16 bytes (63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76)
AES_SBOX0 = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                   0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])
SHA256_EMPTY = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb924"
                             "27ae41e4649b934ca495991b7852b855")


def raw_find(data, pat):
    out, i = [], data.find(pat)
    while i != -1 and len(out) < 8:
        out.append(i)
        i = data.find(pat, i + 1)
    return out


def dword_search_raw(data, dwords):
    """LE dwords appearing contiguously in the file (literal pool / x86 imm)."""
    hits = {}
    for idx, w in enumerate(dwords):
        le = struct.pack("<I", w)
        hits[idx] = raw_find(data, le)
    return hits


# ------------------------------------------------------------------ arm64 ----
def _movz_imm(w):
    # MOVZ (32b): sf=0 op=10 100101 hw imm16 Rd
    if (w & 0x7F800000) == 0x52800000:
        return ((w >> 21) & 3, (w >> 5) & 0xFFFF, w & 0x1F)
    return None


def _movk_imm(w):
    if (w & 0x7F800000) == 0x72800000:
        return ((w >> 21) & 3, (w >> 5) & 0xFFFF, w & 0x1F)
    return None


def arm64_dword_imm_stream(data):
    """Yield (pos, dword, rd) for every movz/movk pair forming a 32-bit
    constant in adjacent-or-near instructions (window 4)."""
    n = len(data) // 4
    words = struct.unpack_from("<%dI" % n, data, 0) if n else ()
    regs = {}          # rd -> (hw_set, value) still open
    out = []
    for i, w in enumerate(words):
        m = _movz_imm(w)
        if m:
            hw, imm, rd = m
            if hw == 0:
                regs[rd] = (0, imm, i)
            continue
        m = _movk_imm(w)
        if m:
            hw, imm, rd = m
            prev = regs.get(rd)
            if prev and prev[0] == 0 and hw == 1:
                val = prev[1] | (imm << 16)
                out.append((prev[2] * 4, val, rd))
                del regs[rd]
            continue
        # any other instruction invalidates rd
        rd = w & 0x1F
        if rd in regs:
            del regs[rd]
    return out


def arm64_imm_hits(data, dwords, mask=None):
    """Find dword immediate values (optionally XOR-masked) in the arm64
    immediate stream. Returns {idx: [pos,...]}."""
    want = {}
    for idx, w in enumerate(dwords):
        want[w] = idx
        if mask:
            want[w ^ mask] = idx
    hits = {idx: [] for idx in range(len(dwords))}
    for pos, val, _rd in arm64_dword_imm_stream(data):
        if val in want:
            hits[want[val]].append(pos)
    return hits


def arm64_movz_run_stats(data, rd=2):
    """Stats of `movz w<rd>,#imm` density: locate unrolled push-site style
    runs (Android KB law: 481 movz w2 + bl sites)."""
    n = len(data) // 4
    words = struct.unpack_from("<%dI" % n, data, 0) if n else ()
    runs, run = [], []
    for i, w in enumerate(words):
        m = _movz_imm(w)
        if m and m[2] == rd and m[0] == 0:
            run.append(i)
        else:
            if len(run) >= 16:
                runs.append((run[0] * 4, len(run)))
            run = []
    if len(run) >= 16:
        runs.append((run[0] * 4, len(run)))
    return runs


def scan(name, data, arm64=True):
    res = {"name": name, "size": len(data)}

    def rec(group, label, hits, note=""):
        res.setdefault(group, {})[label] = hits if note == "" else (hits, note)

    # A. raw contiguous
    raw = {}
    raw["KB[0:16]"] = raw_find(data, KB[0:16])
    raw["KB[112:128]"] = raw_find(data, KB[112:128])
    raw["KB[224:240]"] = raw_find(data, KB[224:240])
    raw["KB full(240)"] = raw_find(data, KB)
    raw["IV2(32)"] = raw_find(data, IV2)
    raw["IV2[:8]"] = raw_find(data, IV2[:8])
    raw["DK(32)"] = raw_find(data, DK)
    raw["DK[:8]"] = raw_find(data, DK[:8])
    raw["SHA256_IV(32)"] = raw_find(data, SHA256_IV)
    raw["SHA256_K[0:16]"] = raw_find(data, SHA256_K0)
    raw["AES_SBOX[0:16]"] = raw_find(data, AES_SBOX0)
    raw["sha256_empty"] = raw_find(data, SHA256_EMPTY)
    res["raw"] = raw

    # B. raw LE dwords
    dk_dw = list(struct.unpack(">8I", DK))
    iv2_dw = list(struct.unpack(">8I", IV2))
    sha_iv_dw = list(struct.unpack(">8I", SHA256_IV))
    res["raw_dwords_DK"] = dword_search_raw(data, dk_dw)
    res["raw_dwords_IV2"] = dword_search_raw(data, iv2_dw)
    res["raw_dwords_SHA256IV"] = dword_search_raw(data, sha_iv_dw)

    # C. arm64 immediates
    if arm64:
        res["imm_DK_plain"] = arm64_imm_hits(data, dk_dw)
        res["imm_IV2_xorCC"] = arm64_imm_hits(data, iv2_dw, mask=0xCCCCCCCC)
        res["imm_SHA256IV_xorCC"] = arm64_imm_hits(data, sha_iv_dw, mask=0xCCCCCCCC)
        sha_k_dw = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
                    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5]
        res["imm_SHA256K_xorAA"] = arm64_imm_hits(data, sha_k_dw, mask=0xAAAAAAAA)
        res["movz_w2_runs>=16"] = arm64_movz_run_stats(data, 2)[:20]
    return res


def summarize(res, secmap=None):
    print(f"\n===== {res['name']} ({res['size']} B) =====")
    for label, hits in res["raw"].items():
        state = "FOUND" if hits else "absent"
        at = ""
        if hits and secmap:
            at = "  @ " + ", ".join(hex(h) + "(" + secmap(h) + ")" for h in hits[:3])
        elif hits:
            at = "  @ " + ", ".join(hex(h) for h in hits[:3])
        print(f"  RAW {label:<18} {state}{at}")
    for group in ("raw_dwords_DK", "raw_dwords_IV2", "raw_dwords_SHA256IV"):
        if group in res:
            hits = res[group]
            n = sum(1 for v in hits.values() if v)
            print(f"  {group}: {n}/8 dwords found as raw LE  "
                  + ", ".join(f"{i}:{len(v)}" for i, v in hits.items() if v))
    for group in ("imm_DK_plain", "imm_IV2_xorCC", "imm_SHA256IV_xorCC",
                  "imm_SHA256K_xorAA"):
        if group in res:
            hits = res[group]
            n = sum(1 for v in hits.values() if v)
            tot = sum(len(v) for v in hits.values())
            det = ", ".join(f"{i}:{[hex(p) for p in v[:2]]}" for i, v in hits.items() if v)
            print(f"  {group}: {n}/8 dwords, {tot} hits   {det}")
    if "movz_w2_runs>=16" in res:
        print(f"  movz w2 runs>=16: {res['movz_w2_runs>=16']}")


def main():
    targets = []
    and_data = open(AND_SO, "rb").read()
    and_sec = macho.sec_of if False else None
    targets.append(("android-arm64-libsigner.so (AAR v5.0.0)", and_data, True, None))

    def load_ios(p, name):
        sl = macho.slices(p)
        s = [x for x in sl if x.name == "arm64"]
        s = s[0] if s else sl[0]          # thin device build is named "native"
        d = s.data
        return d, (lambda off: s.sec_of(off)), name

    d, secf, nm = load_ios(IOS_DEV, "ios-device-arm64")
    targets.append((nm + " (dynamic xcframework)", d, True, secf))
    sim = [x for x in macho.slices(IOS_SIM) if x.name == "arm64"][0]
    targets.append(("ios-sim-arm64 (dynamic xcframework)", sim.data, True,
                    lambda off: sim.sec_of(off)))

    out = {}
    for name, data, arm64, secf in targets:
        r = scan(name, data, arm64)
        summarize(r, secf)
        out[name] = {k: v for k, v in r.items()}

    # static .a raw-only scan (archive file, all members at once)
    a = open(IOS_STATIC_A, "rb").read()
    r = scan("ios-static-AdjustSigSdk.a (raw, all members)", a, arm64=False)
    summarize(r, None)
    out[r["name"]] = r

    with open(os.path.join(HERE, "_sub_core_constscan_out.json"), "w") as f:
        json.dump(out, f, indent=1, default=str)
    print("\nwrote _sub_core_constscan_out.json")


if __name__ == "__main__":
    main()
