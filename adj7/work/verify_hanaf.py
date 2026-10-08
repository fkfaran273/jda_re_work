"""verify_hanaf.py -- H-law verdict on the REAL captured in.hanafintech maps.

For each captured sign() call (via its nSign blob):
  record  = cbc_dec(blob[16:272], blob[:16])          (K from record_0015.json)
  nonce12 = u64le(rec.a) || hex(rec.d);  H = rec.b;  cert40 = rec.c
  claims  = adj7_pure.build_claims(kind, <captured map>)   (variants)
  verdict = sha256_iv0(cert40 || nonce12 || SHA0_HEX || claims) == H
            (REAL DEVICE LAW: the 40-B prefix is the cert SHA-1 ASCII from the
             record's "c" field -- NOT 00*40 as on the emulator no-cert path)
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))          # adj7/adj7_pure.py
sys.path.insert(0, HERE)                               # ks_inverse / spn_round

import adj7_pure as sg
from ks_inverse import cbc_dec

data = json.load(open(os.path.join(HERE, "hanaf_map.json")))
captures = data["captures"]


def parse_record(rec):
    s = rec.split(b"\x00")[0].decode("latin1")
    return (re.search(r'"a":\s*(\d+)', s).group(1),
            re.search(r'"b":\s*"([0-9A-Fa-f]+)"', s).group(1),
            re.search(r'"c":\s*"([^"]*)"', s).group(1),
            re.search(r'"d":\s*"([^"]*)"', s).group(1),
            re.search(r'"e":\s*"([^"]*)"', s).group(1))


results = []
for c in captures:
    kind = c["kind_or_endpoint_hint"]
    blob = bytes.fromhex(c["nsign_blob_hex"])
    dup = blob == bytes.fromhex(c["z22222_blob_hex"])
    rec = cbc_dec(blob[16:272], blob[:16])
    a, b, cert40s, d, e = parse_record(rec)
    nonce12 = int(a).to_bytes(8, "little") + bytes.fromhex(d)
    cert40 = cert40s.encode()

    nmap = c["nsign_map"]
    smap = dict(c["map"])

    variants = {}
    # captured map as-is (nSign merged map, activity_kind/client_sdk present)
    variants["nsign_map as-is"] = sg.build_claims(kind, nmap)
    # with include_block2 setdefaults (no-op when keys present)
    variants["nsign_map +block2"] = sg.build_claims(
        kind, nmap, client_sdk=nmap.get("client_sdk", ""), include_block2=True)
    # sign() entry map (params+globals, before native added its 4 fields)
    variants["sign_map +block2"] = sg.build_claims(
        kind, smap, client_sdk=smap.get("client_sdk", ""), include_block2=True)

    rows = {}
    for name, cl in variants.items():
        for prefix_name, prefix in (("00*40", b"\x00" * 40), ("cert40", cert40)):
            dig = sg.sha256_iv0(prefix + nonce12 + sg.SHA0_HEX.encode() + cl)
            rows["%s | %s" % (name, prefix_name)] = \
                dig.hex().upper() == b.upper()

    verdict = rows.get("nsign_map as-is | cert40")
    results.append({
        "kind": kind, "sign_n": c["sign_n"], "z22222_dup_ok": dup,
        "record_a": a, "record_b": b, "record_c": cert40s, "record_d": d,
        "record_e_is_sha0_empty": e == sg.SHA0_HEX,
        "nonce12_hex": nonce12.hex(),
        "nsign_map_keys": list(nmap),
        "secret_id_in_map": "secret_id" in nmap,
        "app_secret_in_map": "app_secret" in nmap,
        "verdicts": rows,
        "law_verdict": "MATCH" if verdict else "MISMATCH",
    })

    print("=" * 76)
    print("%s (SIGN#%d)  nSign~Z22222 blob dup: %s" % (kind, c["sign_n"], dup))
    print("  a=%s  d=%s  cert40=%s  e==sha256(''): %s"
          % (a, d, cert40s[:16] + "..", e == sg.SHA0_HEX))
    for name, ok in rows.items():
        print("  %-28s %s" % (name, "MATCH" if ok else "mismatch"))
    print("  LAW VERDICT (%s): %s" % (kind, results[-1]["law_verdict"]))
    print("  secret_id in map: %s | app_secret in map: %s"
          % (results[-1]["secret_id_in_map"], results[-1]["app_secret_in_map"]))

json.dump(results, open(os.path.join(HERE, "hanaf_verify.json"), "w"), indent=1)
n_ok = sum(1 for r in results if r["law_verdict"] == "MATCH")
print("\n%d/%d calls MATCH. wrote adj7/work/hanaf_verify.json"
      % (n_ok, len(results)))
