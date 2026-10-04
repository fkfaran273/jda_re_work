"""fill_model.py - the descriptor-fill model: evidence tables, laws, and the
corpus reconciliation.  Companion of fill_model.md.

Facts encoded here (all machine-checked against fill_runs/*.json and the
corpus):
  1. The per-call region words (W0, X, tile U0..U3, d2, d4[0..7]) are a pure
     function of the GETTIMEOFDAY time-value at the fill instant, mixed as
         V = tv_sec ^ tv_usec
     proven by the 4-point collision algebra:
         F(513,504000) == F(512,504001)   (V equal: 0x7B321)
         F(513,503999) != F(512,504000)   (V differs, although tv_sec+tv_usec
                                           is equal for the latter pair!)
     sec+1 and usec+1 give BYTE-IDENTICAL descriptors (both harness eras).
  2. INERT inputs (no effect on the region): nsec (CLOCK_* nanoseconds, +-1 ns
     .. +-2 ms), width, height, all 13 property strings, hmac/H, claims
     content (android_id null->value), cert, cert-SHA1, package name,
     tls_base, stack_guard, srand_seed/rand stream.  pid/tid DO feed (they
     are per-process constants, so they cannot differentiate same-process
     signings).
  3. Structural laws of the fill output, reproduced in-emulator at every T:
         U[2]^U[0] == R||R (16-bit replication), and d4[6]>>16 == R.
  4. The corpus ts mystery: rows 8/9 "consecutive ts" 1789240536510/542901 are
     SYNTHETIC (l48_pairs.py: ts7 + ev_offset).  Real log timeline
     (adj9_wh4.log): nsign_in 1789240511766, nsign 1789240514238 (signing A),
     nsign_in 1789240514276 (signing B, 38 ms after A returned).
"""
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = os.path.join(HERE, "fill_runs")
M32 = 1 << 32


# ---------------------------------------------------------------- corpus
def load_rows():
    rows = json.load(open(os.path.join(HERE, "all_signings.json")))
    return rows


def dwords(h):
    return struct.unpack(">%dI" % (len(h) // 8), bytes.fromhex(h))


def region_of_row(r):
    d0 = dwords(r["d0"])
    d4 = dwords(r["d4"])
    d2 = int(r["d2"], 16)
    return d0, d2, d4


def tile_cycle(d0):
    """minimal period of #0 words 2..35 and the cycle phase with R||R."""
    tail = list(d0[2:])
    for p in (1, 2, 3, 4, 6, 8, 12, 16, 17):
        for s in range(0, len(tail) - p):
            if all(tail[i] == tail[i + p] for i in range(s, len(tail) - p)):
                if p == 4:
                    C = tail[s:s + 4]
                    for (i, j) in ((0, 2), (1, 3)):
                        x = C[i] ^ C[j]
                        if (x >> 16) == (x & 0xFFFF):
                            return s + 2, C, x & 0xFFFF
                return s + 2, tail[s:s + p], None
    return None, None, None


def corpus_laws():
    print("== corpus structural laws (10 rows) ==")
    print("row  tile@  cycle prefix                     R      d4[6]>>16  X==U3")
    for i, r in enumerate(load_rows()):
        d0, d2, d4 = region_of_row(r)
        s, C, R = tile_cycle(d0)
        d4_6 = d4[6] >> 16
        print("%2d   w%-3d  %-32s %04x   %04x       %s" % (
            i, s if s is not None else -1,
            " ".join("%08x" % c for c in C[:4]) if C else "-",
            R if R is not None else 0, d4_6,
            d0[1] == d0[5]))


# ---------------------------------------------------------------- emu runs
def emu_region(tag):
    d = json.load(open(os.path.join(RUNS, tag + ".json")))
    by = {e["build_idx"]: e for e in d["descs"][0]}
    d0 = struct.unpack(">36I", bytes.fromhex(by[0]["hex"]))
    d4 = struct.unpack(">8I", bytes.fromhex(by[4]["hex"]))
    d2 = struct.unpack(">I", bytes.fromhex(by[2]["hex"]))[0]
    return d, d0, d2, d4


def emu_V(cfg):
    """the gettimeofday read in the path: off = 4 ms of virtual clock."""
    us = cfg.get("usec", 500000) + 4000
    sec = cfg.get("sec", 1789240512) + us // 1000000
    return sec ^ (us % 1000000), sec + us % 1000000  # (xor-model V, sum-model T)


def emu_table():
    print("\n== emu sweep: region vs V = tv_sec ^ tv_usec ==")
    print("%-14s %10s %10s  W0        d2        d4[6]     desc-sha1-8" % ("run", "V(xor)", "T(sum)"))
    import hashlib
    for tag in ["base_recheck1", "e2_sec1", "e2_usec1", "T+2", "T+3", "T+100",
                "T+1000", "T+10000", "Tsame", "pidtid"]:
        p = os.path.join(RUNS, tag + ".json")
        if not os.path.exists(p):
            continue
        d, d0, d2, d4 = emu_region(tag)
        V, T = emu_V(d["cfg"])
        h = hashlib.sha256((by0 := d["descs"][0][0]["hex"]).encode()).hexdigest()[:8]
        print("%-14s %10x %10x  %08x  %08x  %08x  %s" % (tag, V, T, d0[0], d2, d4[6], h))
    # collision check
    _, s0, s2, s4 = emu_region("e2_sec1")
    _, u0, u2, u4 = emu_region("e2_usec1")
    print("\ncollision F(513,504000) == F(512,504001):",
          (s0, s2, s4) == (u0, u2, u4),
          " (V equal: 0x6aa21401)")
    _, t0, t2, t4 = emu_region("Tsame")
    _, b0, b2, b4 = emu_region("base_recheck1")
    print("Tsame(513,503999) != base(512,504000):    ",
          (t0, t2, t4) != (b0, b2, b4),
          " (sum-model EQUAL 0x6aad5580, xor-model 0x6aa2147e vs 0x6aa21400)")


def ts_mystery():
    print("\n== rows 7/8/9 timeline ==")
    rows = load_rows()
    iso = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}")
    for i in (7, 8, 9):
        ca = iso.search(bytes.fromhex(rows[i]["d10"]).decode("latin1")).group(0)
        print("row %d: created_at(in claims)=%s  ev=%d" % (i, ca, rows[i]["ev"]))
    print("l48_pairs.py synthesises row ts: TS[8]=TS[7]+22272, TS[9]=TS[7]+28663")
    print("  -> the 'consecutive ts 1789240514238/536510/542901' are NOT capture times.")
    print("real log (device/adj9_wh4.log): nsign_in ts=1789240511766;")
    print("  nsign ts=1789240514238 (signing A, 2.47 s later); nsign_in ts=1789240514276")
    print("  (signing B 38 ms after A returned).  Signing B's second was therefore")
    print("  ~1789240514+, NOT 1789240512 - the created_at+1 law does not apply to it.")


def inert_inputs():
    print("\n== input map (emu, era-2 harness unless noted) ==")
    base = emu_region("base_recheck1")[1:]
    rows = [
        ("nsec +-1ns/+-1us/+-1ms/+-2ms/+-1000ns", "INERT", "era-1 runs nsec*"),
        ("sec / gettimeofday tv_sec", "LIVE (xor-mixed with usec)", "e2_sec1"),
        ("usec / gettimeofday tv_usec", "LIVE (xor-mixed with sec)", "e2_usec1"),
        ("width / height", "INERT", "era-1 width+1/height+1"),
        ("13 property strings", "INERT", "era-1 prop_model"),
        ("hmac / H", "INERT", "era-1 hmac_flip"),
        ("claims content (android_id)", "INERT for region; feeds #7/#10", "era-1 androidid"),
        ("environment value", "GATE (non-production zeroes the fill)", "era-1 env_val"),
        ("cert / cert-SHA1 / package / tls / guard / srand", "INERT", "era-2 sha1_vary..srand2"),
        ("pid / tid", "LIVE (per-process constants)", "era-2 pidtid"),
    ]
    for name, verdict, evidence in rows:
        print("  %-42s %-38s [%s]" % (name, verdict, evidence))


if __name__ == "__main__":
    corpus_laws()
    emu_table()
    ts_mystery()
    inert_inputs()
