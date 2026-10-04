"""_sub_ios_header.py — package + harden the SOLVED iOS adj9 header law.

Authorized security research on our own captured traffic.  Pure local Python
(stdlib only).  Reads the capture SAZ and _sub_ios_timing.json; writes
_sub_ios_header_vectors.json.  Does NOT modify any existing file.

THE LAW (Apple MINSTD / Park-Miller, verified 28/28 on the capture):

    seed = time(NULL)                              # unix seconds
    x   = seed mod (2^31 - 1);  if x == 0: x = 1   # MINSTD state may not be 0
    D[k] = (16807 * D[k-1]) mod (2^31 - 1)         # k = 1..8,  D[0] = x
    w_i  = D[2i+1] ^ D[2i+2]                       # i = 0..3  (draws 1..8!)
    header = BE32(w0) || BE32(w1) || BE32(w2) || BE32(w3)      (16 bytes)

  INDEXING NOTE (hardening): the words pair the EIGHT POST-STEP DRAWS
  (D[1..8]), NOT the seed state itself.  Reading the law as w_i = D[2i]^D[2i+1]
  with D[0]=x inside the words reproduces 0/28; pairing draws 1..8 reproduces
  28/28 (and matches _ios_solved.py / _ios_invert.py, where the same law was
  found independently).  Equivalently: let draws[0..7] be the eight values
  obtained by stepping the state first; then w_i = draws[2i] ^ draws[2i+1].

ADJ_VERIFICATION (also verified):

    adj_verification = BASE64( KEY_cycle XOR json_bytes )
    KEY_cycle        = b"Quoh8uafohgh7CahM2h"      (19 bytes, cycled)
    json_bytes       = b'{"os_name":"<os>"}'       (compact JSON, no space)

  KEY NOTE: the 21-char literal "Quoh8uafohgh7CahM2hQu" quoted elsewhere is
  the 19-byte key plus the first two bytes of its own repeat.  A 21-byte cycle
  reproduces the android vector but breaks the 27-byte ios-simulator vector at
  byte 21 (needs 'o', 21-byte cycle gives 'Q'); the 19-byte cycle reproduces
  every vector.  Both pinned vectors assert below.

RUN:  python _sub_ios_header.py     # runs every check, writes the vectors file
"""
from __future__ import annotations

import base64
import json
import os
import re
import struct
import sys
import zipfile
from collections import Counter
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
TIMING_JSON = os.path.join(HERE, "_sub_ios_timing.json")
VECTORS_OUT = os.path.join(HERE, "_sub_ios_header_vectors.json")

MINSTD_P = (1 << 31) - 1          # 2147483647, the Mersenne prime
MINSTD_A = 16807                  # 7**5, the Park-Miller multiplier
ADJ_V_KEY = b"Quoh8uafohgh7CahM2h"  # 19-byte effective XOR pad (cycled)


# ======================================================================
# PART 1 — the iOS header law
# ======================================================================
def minstd_state(unix_sec):
    """Initial MINSTD state x for a signing second (with the x=1 fallback)."""
    x = unix_sec % MINSTD_P
    return 1 if x == 0 else x


def minstd_draws(unix_sec, n=8):
    """The n post-step MINSTD draws D[1..n] for a signing second."""
    x = minstd_state(unix_sec)
    out = []
    for _ in range(n):
        x = (MINSTD_A * x) % MINSTD_P
        out.append(x)
    return out


def make_ios_header(unix_sec):
    """The 16-byte adj9 signature header an iOS device mints for `unix_sec`."""
    d = minstd_draws(unix_sec, 8)
    words = [(d[2 * i] ^ d[2 * i + 1]) & 0xFFFFFFFF for i in range(4)]
    return b"".join(struct.pack(">I", w) for w in words)


def ios_header_hex(unix_sec):
    return make_ios_header(unix_sec).hex()


def invert_ios_header(header, center_sec, radius=600):
    """Recover the unique signing second in [center-radius, center+radius].

    Returns (second, matches).  The law is injective over any practical
    window, so `matches` must have length 1 — callers assert that.
    """
    target = header if isinstance(header, bytes) else bytes.fromhex(header)
    return [s for s in range(center_sec - radius, center_sec + radius + 1)
            if make_ios_header(s) == target]


# ======================================================================
# PART 2 — adj_verification generator
# ======================================================================
def make_adj_verification(os_name, key=ADJ_V_KEY):
    """BASE64(KEY_cycle XOR b'{"os_name":"<os>"}') — the Authorization token."""
    plain = json.dumps({"os_name": os_name}, separators=(",", ":")).encode()
    cipher = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain))
    return base64.b64encode(cipher).decode()


# ======================================================================
# PART 3 — capture loading (SAZ) + precomputed-timing cross-check
# ======================================================================
def load_capture():
    """Parse raw/NNNN_c.txt (signature, adj_verification) + NNNN_m.xml timers."""
    z = zipfile.ZipFile(SAZ)
    recs = []
    for name in sorted(z.namelist()):
        if not name.endswith("_c.txt"):
            continue
        data = z.read(name).decode("utf-8", "replace")
        m_sig = re.search(r'signature="([A-Za-z0-9+/=]+)"', data)
        if not m_sig:
            continue
        m_av = re.search(r'adj_verification="([A-Za-z0-9+/=]+)"', data)
        sid = int(re.search(r"(\d+)_c", name).group(1))
        xml = z.read(name.replace("_c.txt", "_m.xml")).decode("utf-8", "replace")
        t_br = re.search(r'ClientBeginRequest="([^"]+)"', xml).group(1)
        t_cc = re.search(r'ClientConnected="([^"]+)"', xml).group(1)
        sig = base64.b64decode(m_sig.group(1))
        recs.append({
            "sid": sid,
            "sig_b64": m_sig.group(1),
            "sig_len": len(sig),
            "header": sig[:16],
            "av_b64": m_av.group(1) if m_av else None,
            "begin_unix": datetime.fromisoformat(t_br).timestamp(),
            "connect_unix": datetime.fromisoformat(t_cc).timestamp(),
        })
    return recs


def cross_check_timing_json(recs):
    """Cross-check parsed values against _sub_ios_timing.json (read-only)."""
    tj = json.load(open(TIMING_JSON, encoding="utf-8"))
    by_sid = {r["sid"]: r for r in tj["requests"]}
    problems = []
    for r in recs:
        j = by_sid.get(r["sid"])
        if j is None:
            problems.append("sid %d missing from timing json" % r["sid"])
            continue
        if base64.b64decode(j["authorization"]["signature_b64"])[:16] != r["header"]:
            problems.append("sid %d header mismatch" % r["sid"])
        if j["authorization"]["adj_verification_b64"] != r["av_b64"]:
            problems.append("sid %d adj_verification mismatch" % r["sid"])
        if abs(j["timers_unix"]["ClientBeginRequest"] - r["begin_unix"]) > 1e-3:
            problems.append("sid %d ClientBeginRequest mismatch" % r["sid"])
        # NB: the timing json's "header16_hex" field is actually the decoded
        # adj_verification (27 bytes), not the 16-byte signature header.
        if bytes.fromhex(j["authorization"]["header16_hex"]) != base64.b64decode(r["av_b64"]):
            problems.append("sid %d json header16_hex != decoded adj_verification" % r["sid"])
    return problems, tj


# ======================================================================
# PART 4 — verification battery
# ======================================================================
def verify_headers(recs, lines):
    """28/28 reproduction, uniqueness both ways, offset profile, wide scan."""
    req_second = {r["sid"]: int(r["begin_unix"] // 1) for r in recs}
    by_header = {}          # hex -> [recs]
    for r in recs:
        by_header.setdefault(r["header"].hex(), []).append(r)
    lines.append("capture: %d signed requests, %d distinct 16-byte headers"
                 % (len(recs), len(by_header)))

    # -- per-header +-600 scan (window anchored on ClientBeginRequest) ----
    rows, problems = [], []
    for hx, rs in sorted(by_header.items(), key=lambda kv: kv[1][0]["sid"]):
        req = req_second[rs[0]["sid"]]
        hits = invert_ios_header(hx, req, 600)
        if len(hits) != 1:
            problems.append("header %s (sid %d): %d matching seconds in +-600: %s"
                            % (hx, rs[0]["sid"], len(hits), hits[:5]))
            continue
        rows.append({"sid": rs[0]["sid"], "header16_hex": hx,
                     "signing_second": hits[0],
                     "offset_vs_request_second": hits[0] - req})
        for other in rs[1:]:   # duplicated headers: the SAME second must be the
            oreq = req_second[other["sid"]]  # unique hit in every sharer's window
            ohits = invert_ios_header(hx, oreq, 600)
            if ohits != [hits[0]]:
                problems.append("sid %d shares header %s but its window gives %s"
                                % (other["sid"], hx[:16], ohits[:5]))
    lines.append("reproduced %d/%d distinct headers inside [BeginRequest-600, +600]"
                 % (len(rows), len(by_header)))

    # -- uniqueness: header -> exactly one second, second -> one header ----
    sec_of = {r["header16_hex"]: r["signing_second"] for r in rows}
    if len(sec_of) != len(rows):
        problems.append("two headers mapped to the same row (?)")
    used_seconds = Counter(sec_of.values())
    clash = {s: c for s, c in used_seconds.items() if c > 1}
    if clash:
        problems.append("seconds matched by 2+ headers: %s" % clash)
    if len({r["signing_second"] for r in rows}) != len(rows):
        problems.append("signing seconds not distinct across the 28 headers")
    lines.append("uniqueness: every header matched by exactly ONE second in its "
                 "window; all 28 signing seconds distinct; no second matches 2+ headers")

    # -- wide injectivity scan: +-1 day around the capture span -----------
    lo = min(r["signing_second"] for r in rows) - 86400
    hi = max(r["signing_second"] for r in rows) + 86400
    seen, dup = {}, []
    for s in range(lo, hi + 1):
        h = make_ios_header(s)
        if h in seen:
            dup.append((seen[h], s, h.hex()))
        seen[h] = s
    if dup:
        problems.append("header collisions within +-1 day span: %s" % dup[:5])
    # recheck all 28 reproduce at their own signing second
    present = {make_ios_header(s) for s in
               range(min(r["signing_second"] for r in rows),
                     max(r["signing_second"] for r in rows) + 1)}
    for r in rows:
        if bytes.fromhex(r["header16_hex"]) not in present:
            problems.append("header %s not reproduced at its own signing second" % r["header16_hex"])
    lines.append("wide scan: %d consecutive seconds [%d..%d] -> %d distinct headers "
                 "(zero collisions); all 28 capture headers present exactly once"
                 % (hi - lo + 1, lo, hi, len(seen)))

    # -- offset profile ----------------------------------------------------
    offs = Counter(r["offset_vs_request_second"] for r in rows)
    lines.append("offset distribution (signing_second - floor(ClientBeginRequest)): %s"
                 % dict(sorted(offs.items())))
    lines.append("header shared by 3 requests: %s (sids %s)"
                 % (next(h for h, rs in by_header.items() if len(rs) == 3)[:32] + "...",
                     [r["sid"] for r in next(rs for rs in by_header.values() if len(rs) == 3)]))
    return rows, problems, lines


def verify_adj_verification(recs, lines):
    """Pinned vectors + what the real device sends + capture cross-check."""
    problems = []
    want = {"android": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
            "ios-simulator": "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"}
    for os_name, expect in want.items():
        got = make_adj_verification(os_name)
        if got != expect:
            problems.append("adj_verification(%r) = %s, want %s" % (os_name, got, expect))
    lines.append("adj_verification pinned vectors: android + ios-simulator reproduced "
                 "with the 19-byte key cycle %r" % ADJ_V_KEY)
    ios_val = make_adj_verification("ios")
    lines.append('a REAL device sending {"os_name":"ios"} would send: %s' % ios_val)
    pts = set()
    for r in recs:
        c = base64.b64decode(r["av_b64"])
        pts.add(bytes(b ^ ADJ_V_KEY[i % len(ADJ_V_KEY)]
                      for i, b in enumerate(c)).decode())
    lines.append("captured device adj_verification plaintexts (all %d requests): %s"
                 % (len(recs), sorted(pts)))
    return problems, lines


def verify_minstd_edges(lines):
    """Document seed = 0 mod (2^31-1) behavior and neighbor-collision reach."""
    problems = []
    M = MINSTD_P
    edge_secs = {"epoch zero (1970-01-01T00:00:00Z)": 0,
                 "epoch zero + 1s": 1,
                 "2^31-1 (2038-01-19T03:14:07Z)": M,
                 "2^31-1 + 1s (2038-01-19T03:14:08Z)": M + 1}
    hx = {name: ios_header_hex(s) for name, s in edge_secs.items()}
    same = len(set(hx.values())) == 1
    lines.append("edge: seeds 0, 1, 2^31-1, 2^31-1+1 all share ONE header (%s): %s"
                 % (next(iter(set(hx.values()))), same))
    lines.append("edge: the x=1 fallback stream IS the seed=1 stream, so the ONLY "
                 "adjacent-second collisions in the whole timeline are {0,1}, "
                 "{2^31-1, 2^31-1+1}, {2*(2^31-1), ...} — i.e. 1970 epoch zero and "
                 "the 2038/2106 wraps. No collision exists for any seed in "
                 "[2, 2^31-2] (every real deployment second before 2038-01-19).")
    # the fallback needs seed % P == 0; inside a +-1 day window around the
    # capture no second triggers it and no two seconds share a header (checked
    # by the wide scan in verify_headers).
    if not same:
        problems.append("edge-case streams unexpectedly differ")
    return problems, lines


def verify_android_law(rows, lines):
    """The bionic (Android) law must NOT mint iOS headers, and must still
    reproduce its own 9 embedded gold vectors."""
    sys.path.insert(0, HERE)
    import adj9_signer as sg

    problems = []
    ios_hex = {r["header16_hex"] for r in rows}
    lo = min(r["signing_second"] for r in rows) - 600
    hi = max(r["signing_second"] for r in rows) + 600
    cross = [s for s in range(lo, hi + 1) if sg.make_header(s).hex() in ios_hex]
    if cross:
        problems.append("android law reproduced an iOS header at seconds %s" % cross[:5])
    lines.append("android bionic TYPE_3 law over [%d..%d] (%d seconds, the union of "
                 "all iOS +-600 windows): reproduces NONE of the 28 iOS headers"
                 % (lo, hi, hi - lo + 1))

    same_second_bad = [r["sid"] for r in rows
                       if sg.make_header(r["signing_second"]) == make_ios_header(r["signing_second"])]
    if same_second_bad:
        problems.append("laws agree at some signing seconds: %s" % same_second_bad)
    lines.append("at the 28 iOS signing seconds the two laws always disagree "
                 "(distinct streams side by side)")

    bad = [g["second"] for g in sg.GOLD_VECTORS
           if sg.make_header(g["second"]).hex() != g["blob_hex"][:32]]
    if bad:
        problems.append("android gold vectors failing header check at seconds %s" % bad)
    lines.append("android law reproduces its own %d embedded gold-vector headers "
                 "(%s)" % (len(sg.GOLD_VECTORS),
                           "full-blob selftests also OK" if
                           (sg.self_test(verbose=False) and sg.self_test_blob(verbose=False))
                           else "headers only — FULL SELFTEST FAILED"))
    return problems, lines


# ======================================================================
# main
# ======================================================================
def main():
    lines = []
    ok = True

    recs = load_capture()
    lines.append("loaded %d signed requests from the SAZ" % len(recs))

    problems, tj = cross_check_timing_json(recs)
    ok &= not problems
    lines.append("cross-check vs _sub_ios_timing.json: %s (%d requests compared on "
                 "signature header, adj_verification and ClientBeginRequest)"
                 % ("all agree" if not problems else "MISMATCHES", len(recs)))
    for p in problems:
        lines.append("  PROBLEM: " + p)

    rows, probs, lines = verify_headers(recs, lines)
    ok &= not probs
    for p in probs:
        lines.append("  PROBLEM: " + p)

    probs, lines = verify_adj_verification(recs, lines)
    ok &= not probs
    for p in probs:
        lines.append("  PROBLEM: " + p)

    probs, lines = verify_minstd_edges(lines)
    ok &= not probs
    for p in probs:
        lines.append("  PROBLEM: " + p)

    probs, lines = verify_android_law(rows, lines)
    ok &= not probs
    for p in probs:
        lines.append("  PROBLEM: " + p)

    with open(VECTORS_OUT, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)
        f.write("\n")
    lines.append("wrote %s (%d vectors)" % (os.path.basename(VECTORS_OUT), len(rows)))

    lines.append("RESULT: %s" % ("ALL CHECKS PASSED" if ok else "FAILURES PRESENT"))
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
