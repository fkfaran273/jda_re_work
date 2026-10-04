"""_sub_unseal_ios.py — unseal all 30 iOS adj9 bodies from the Cainiao SAZ
capture with whiten_inverse (validated in _sub_unseal_core.py).

Per request:
  blob(192) = header(16) || body(144) || digest(32)   [signature="BASE64"]
  digest check: predict_digest(body) == digest        (shared MAC key K)
  record = whiten_inverse(body, header)
  record layout constants (THE cipher-sharing verdict)
  extract: cert SHA-1 (rec[25:45]), S (rec[20:24] BE32), d0 head (rec[3:19])
  header law cross-check vs MINSTD make_header(second) from _sub_ios_timing.json
  bonus: region-law d0 head reproduction + selector head-phase search.

Read-only w.r.t. adj9_signer.py and the capture.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import sys
import zipfile

import adj9_signer as sg
from _sub_unseal_core import (whiten_inverse, record_constant_checks,
                              SHA0, SBOX_INV, _pi1_inv, _F_inv_chunk)

HERE = os.path.dirname(os.path.abspath(__file__))
SAZ = r"C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
TIMING = os.path.join(HERE, "_sub_ios_timing.json")


# ------------------------------------------------------------- extraction
def extract_signed_blobs(saz_path):
    """All raw/*_c.txt client requests whose Authorization carries
    signature="BASE64" decoding to a 192-B blob."""
    z = zipfile.ZipFile(saz_path)
    pat = re.compile(r'signature="([A-Za-z0-9+/=]+)"')
    sdk_pat = re.compile(r'(?im)^Client-Sdk:\s*(\S+)')
    path_pat = re.compile(r'(?m)^(?:POST|GET)\s+(\S+)')
    found = []
    names = sorted(n for n in z.namelist()
                   if re.fullmatch(r"raw/\d+_c\.txt", n))
    for n in names:
        try:
            txt = z.read(n).decode("latin1")
        except Exception:
            continue
        m = pat.search(txt)
        if not m:
            continue
        try:
            blob = base64.b64decode(m.group(1))
        except Exception:
            continue
        sdk = sdk_pat.search(txt)
        pm = path_pat.search(txt)
        found.append({
            "file": os.path.basename(n),
            "blob": blob,
            "len": len(blob),
            "client_sdk": sdk.group(1) if sdk else None,
            "path": pm.group(1) if pm else None,
        })
    return found


# --------------------------------------------------- d0 head <-> selectors
def selector_halfword(mask, source):
    return sg._selector_halfword(mask, source)


def d0_head_to_selectors(head16):
    """record[3:19] -> the 8 d0 selector halfwords (big-endian 16-bit)."""
    return [int.from_bytes(head16[2 * i:2 * i + 2], "big") for i in range(8)]


def head_phase_search(S, rec_head16):
    """Find the d0 selector head phase that reproduces rec_head16 for seed S.

    selectors[i] = head[i] for i < len(head), else (0x40 | (i & 7)).
    The record head exposes selectors 0..7.  We test whether positions 2..7
    match the stable cycle, then solve positions 0 and 1 by brute force over
    the 8-bit selector domain 0..126 (the signer's own random-phase domain)."""
    source = sg._d0_source(sg._d4_words(S & 0xFFFFFFFF))
    vals = d0_head_to_selectors(rec_head16)

    cycle_ok = all(
        selector_halfword(((0x40 | (i & 7)) << 1) + 3, source) == vals[i]
        for i in range(2, 8))

    sols0 = [h for h in range(127)
             if selector_halfword((h << 1) + 3, source) == vals[0]]
    matches = []
    for h0 in sols0:
        # phase length 1: selector[1] = cycle 0x41
        if selector_halfword(((0x40 | 1) << 1) + 3, source) == vals[1]:
            head = (h0,)
            if sg.head16_for(S, head=head) == rec_head16:
                matches.append(list(head))
        # phase length 2: selector[1] = free h1
        for h1 in range(127):
            if selector_halfword((h1 << 1) + 3, source) == vals[1]:
                head = (h0, h1)
                if sg.head16_for(S, head=head) == rec_head16:
                    matches.append(list(head))
    return cycle_ok, matches


# ------------------------------------------------------------------- main
def gold_phase_sanity():
    """Sanity: the head-phase search must rediscover the stored Android
    head phases from the gold records alone."""
    out = []
    for g in sg.GOLD_VECTORS:
        blob = bytes.fromhex(g["blob_hex"])
        rec = whiten_inverse(blob[16:160], blob[:16])
        _, matches = head_phase_search(g["S"], rec[3:19])
        out.append({"app": g["app"], "kind": g["kind"],
                    "stored_head": list(g["head"]), "found": matches,
                    "ok": list(g["head"]) in matches})
    return out


def main():
    timing = json.load(open(TIMING))
    tmap = {r["file"]: r for r in timing["requests"]}

    found = extract_signed_blobs(SAZ)
    print("[ios] SAZ client requests scanned; adj9-signed found: %d"
          % len(found))
    print("[ios] SDKs seen on signed requests: %s"
          % sorted({f["client_sdk"] for f in found}))
    print("[ios] paths: %s" % sorted({f["path"] for f in found}))

    tfiles = set(tmap)
    ffiles = {f["file"] for f in found}
    print("[ios] file-set matches _sub_ios_timing.json: %s"
          % ("YES" if tfiles == ffiles else
             "NO (timing-only=%s found-only=%s)"
             % (sorted(tfiles - ffiles)[:5], sorted(ffiles - tfiles)[:5])))

    results = []
    verdict_counts = {}
    certs = {}
    head_phases = {}
    dev_fields = {}
    variant112 = {}

    sanity = gold_phase_sanity()
    print("\n[ios] head-phase search sanity on 9 Android gold vectors: %s"
          % ("ALL OK" if all(s["ok"] for s in sanity) else "FAIL"))
    for s in sanity:
        print("   gold %-9s %-11s stored=%s found=%s"
              % (s["app"], s["kind"], s["stored_head"], s["found"]))

    for f in found:
        blob = f["blob"]
        header, body, digest = blob[:16], blob[16:160], blob[160:192]
        t = tmap.get(f["file"], {})

        dig_ok = len(digest) == 32 and sg.predict_digest(body) == digest

        rec = whiten_inverse(body, header)
        checks = record_constant_checks(rec)
        S = int.from_bytes(rec[20:24], "big")
        cert = rec[25:45]
        d0head = rec[3:19]

        # iOS-variant field anatomy (deviations from the Android record)
        variant112[rec[112]] = variant112.get(rec[112], 0) + 1
        dev = rec[114:130]                       # 16-B field between 07 and 0e*
        dev_fields.setdefault(dev, []).append(f["file"])

        # header law: MINSTD XOR-pair header for the capture's signing second
        # (candidates from the timing JSON, plus a +-10 s brute-force sweep)
        hdr_hits = []
        cands = set((t.get("signing_seconds") or {}).get("candidates", []))
        for c in list(cands):
            cands.update(range(int(c) - 10, int(c) + 11))
        for sec in sorted(cands):
            try:
                if sg.make_header(int(sec)) == header:
                    hdr_hits.append(int(sec))
            except Exception:
                pass

        # timing-JSON cross-checks
        b64_ok = None
        h16_ok = None
        if t:
            sb = (t.get("authorization") or {}).get("signature_b64")
            b64_ok = (base64.b64encode(blob).decode() == sb) if sb else None
            hh = (t.get("authorization") or {}).get("header16_hex")
            h16_ok = (header.hex() == hh) if hh else None

        cycle_ok, phases = head_phase_search(S, d0head)
        for ph in phases:
            head_phases.setdefault(tuple(ph), []).append(f["file"])

        certs.setdefault(cert.hex(), []).append(f["file"])

        r = {
            "file": f["file"], "path": f["path"], "client_sdk": f["client_sdk"],
            "header16_hex": header.hex(),
            "digest_ok": bool(dig_ok),
            "S": S, "S_hex": rec[20:24].hex(),
            "cert_sha1_hex": cert.hex(),
            "d0_head_hex": d0head.hex(),
            "byte111": rec[111], "byte112_variant": rec[112],
            "byte113": rec[113],
            "field114_129_hex": rec[114:130].hex(),
            "field114_129_ascii": "".join(chr(b) if 32 <= b < 127 else "."
                                          for b in rec[114:130]),
            "constants": {k: bool(v) for k, v in checks.items()},
            "header_law_seconds": hdr_hits,
            "timing_b64_match": b64_ok, "timing_header16_match": h16_ok,
            "d0_cycle_ok": bool(cycle_ok),
            "head_phase_matches": phases,
        }
        results.append(r)
        for k, v in checks.items():
            verdict_counts[k] = verdict_counts.get(k, 0) + v
        verdict_counts["digest_ok"] = verdict_counts.get("digest_ok", 0) + bool(dig_ok)
        verdict_counts["header_law_ok"] = verdict_counts.get("header_law_ok", 0) + bool(hdr_hits)

    n = len(results)
    print("\n[ios] VERDICT COUNTS over %d iOS bodies:" % n)
    for k, v in sorted(verdict_counts.items()):
        print("   %-26s %3d/%d %s" % (k, v, n, "OK" if v == n else "MISMATCH"))

    print("\n[ios] byte112 variant values: %s" % variant112)
    print("[ios] byte111==0x06 on %d/%d; byte113==0x07 on %d/%d"
          % (sum(1 for r in results if r["byte111"] == 6), n,
             sum(1 for r in results if r["byte113"] == 7), n))
    print("\n[ios] distinct field114_129 values: %d" % len(dev_fields))
    for dv, fl in dev_fields.items():
        print("   %s  ascii=%r  x%d  (e.g. %s)"
              % (dv.hex(), "".join(chr(b) if 32 <= b < 127 else "."
                                   for b in dv), len(fl), fl[0]))

    # phase (0x40,) vs (0x40,0x41) equivalence and Android contrast
    s0 = results[0]["S"]
    same = (sg.head16_for(s0, head=(0x40,)) == sg.head16_for(s0, head=(0x40, 0x41)))
    differs = (sg.head16_for(s0, head=(0x40,)) != sg.head16_for(s0, head=(0x2B,)))
    print("[ios] phase (0x40,) == (0x40,0x41) selector-wise: %s;  "
          "differs from Android (0x2B,): %s" % (same, differs))

    print("\n[ios] cert SHA-1 values: %d distinct" % len(certs))
    for c, fl in certs.items():
        print("   %s  x%d  (e.g. %s)" % (c, len(fl), fl[0]))

    print("\n[ios] head phases reproducing d0 head via region(S):")
    for ph, fl in sorted(head_phases.items()):
        print("   head=%-12s x%d" % (ph, len(fl)))

    print("\n[ios] per-request:")
    for r in results:
        print("   %s %-38s dig=%s const=%d/10 hdr=%s S=%u cert=%s d0=%s phase=%s"
              % (r["file"], r["path"] or "?",
                 "OK" if r["digest_ok"] else "FAIL",
                 sum(r["constants"].values()),
                 r["header_law_seconds"] or "-",
                 r["S"], r["cert_sha1_hex"][:16] + "..",
                 r["d0_head_hex"], r["head_phase_matches"]))

    # ---------------- hex dumps of the first 3 records
    print("\n[ios] hex dumps of first 3 unsealed records:")
    dumps = []
    for r in results[:3]:
        f = next(x for x in found if x["file"] == r["file"])
        rec = whiten_inverse(f["blob"][16:160], f["blob"][:16])
        lines = []
        for off in range(0, 144, 16):
            chunk = rec[off:off + 16]
            lines.append("  %03x: %s  %s"
                         % (off, chunk.hex(" "),
                            "".join(chr(b) if 32 <= b < 127 else "."
                                    for b in chunk)))
        dump = "%s S=%u cert=%s\n%s" % (r["file"], r["S"],
                                        r["cert_sha1_hex"],
                                        "\n".join(lines))
        dumps.append(dump)
        print(dump)

    out = {
        "saz": os.path.basename(SAZ),
        "n_found": n,
        "verdict_counts": verdict_counts,
        "cert_values": {c: fl for c, fl in certs.items()},
        "head_phases": {str(k): v for k, v in head_phases.items()},
        "variant112": variant112,
        "field114_129": {dv.hex(): {"ascii": "".join(chr(b) if 32 <= b < 127
                                                    else "." for b in dv),
                                    "files": fl}
                         for dv, fl in dev_fields.items()},
        "gold_phase_sanity": sanity,
        "results": results,
        "hex_dumps_first3": dumps,
    }
    with open(os.path.join(HERE, "_sub_unseal_ios_out.json"), "w") as fh:
        json.dump(out, fh, indent=1)
    print("\n[ios] wrote _sub_unseal_ios_out.json")

    core = ("magic_rec0_2_is_010008", "sep19_is_0x02", "sep24_is_0x03",
            "sep45_is_0x04", "sep78_is_0x05", "sha256_empty_at_79_110",
            "zero2_at_128_129", "tail_0e14_at_130_143", "digest_ok")
    all_core = all(verdict_counts.get(k, 0) == n for k in core)
    print("[ios] CIPHER-SHARING VERDICT: %s"
          % ("ALL CORE CONSTANTS + DIGEST VALIDATE — body cipher and record "
             "law shared with Android" if all_core
             else "CORE CONSTANTS DO NOT ALL VALIDATE"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
