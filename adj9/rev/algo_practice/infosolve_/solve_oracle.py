"""solve_oracle.py -- settle the info claims law with the block oracle.

Rows:
  * 3 info signings from event_vectors.json (oracle_run3, 9 Sep, moto g42)
  * 1 info signing from saz_vectors.json   (Fiddler saz, 8 Sep, OnePlus)
  * calibration rows of the solved kinds (session/click/attribution/event)
    from both captures, to prove the oracle plumbing.

The mapget hook (adj9/device/adj9_wh.log) shows the signer queries exactly
    adj_verification android_uuid app_token created_at environment
    gps_adid gps_adid_src push_token source tracking_enabled
    (+ envelope: adj_signing_id, activity_kind, client_sdk, headers_id,
      native_version -- the last three and the PIN are not map.get calls)
in that (sorted) order, twice per signing.  The only unknown is where the PIN
splits the sorted list, so try every split, plus no-PIN, on every row.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MRUN = r"C:\Users\Apps\Downloads\com.penti.app\manual_run"
sys.path.insert(0, MRUN)
import adj9_pure as P          # noqa: E402
import adj9_decode as D        # noqa: E402
from urllib.parse import parse_qs  # noqa: E402

APPS = json.load(open(os.path.join(MRUN, "apps.json")))["penti"]
ADJ_VER = APPS["adj_verification"]
CLIENT_SDK = APPS["client_sdk"]
HEADERS_ID = APPS["headers_id"]
NATIVE = APPS["native_version"]
PIN = APPS["adj_signing_id"]


def decode(blob_hex):
    blob = bytes.fromhex(blob_hex)
    rec = D.whiten_body_inverse(blob[16:160], blob[:16])
    assert rec[0:3] == b"\x01\x00\x08", rec[:3].hex()
    assert rec[19] == 2 and rec[24] == 3 and rec[45] == 4 and rec[78] == 5
    return {
        "seed": struct.unpack(">I", rec[20:24])[0],
        "head": rec[3:19],
        "cert": rec[25:45],
        "want": rec[46:78],
        "blob": blob,
    }


def block_ok(row, claims):
    got = P.record_block(row["head"], row["seed"], claims, row["cert"])
    return got == row["want"]


# ---------------------------------------------------------------- rows
rows = []          # (label, kind, values, decoded)

saz = json.load(open(os.path.join(MRUN, "saz_vectors.json")))
for kind in ("session", "click", "info", "attribution"):
    r = saz[kind]
    d = decode(r["sig_hex"])
    # cross-check against the pre-decoded fields shipped in the file
    assert d["seed"] == r["seed"], (kind, d["seed"], r["seed"])
    assert d["head"].hex() == r["head_hex"]
    assert d["cert"].hex() == r["cert_hex"]
    assert d["want"].hex() == r["block_hex"]
    val = {k: v[0] for k, v in parse_qs(r["form"]).items()}
    if not r["form"]:                      # attribution: form lives in the URL
        val = {k: v[0] for k, v in
               parse_qs(r["path"].split("?", 1)[1]).items()}
    val.setdefault("activity_kind", kind)
    val.setdefault("client_sdk", CLIENT_SDK)
    val.setdefault("adj_verification", ADJ_VER)
    val.setdefault("adj_signing_id", PIN)
    val.setdefault("headers_id", HEADERS_ID)
    val.setdefault("native_version", NATIVE)
    rows.append(("saz:" + kind, kind, val, d))

for i, v in enumerate(json.load(open(os.path.join(MRUN, "event_vectors.json")))):
    d = decode(v["blob"])
    kind = v["map"]["activity_kind"]
    rows.append(("ev%d:%s" % (i, kind), kind, dict(v["map"]), d))

# ------------------------------------------------- calibration (solved kinds)
print("== calibration of the solved laws (block oracle) ==")
calib_ok = True
for label, kind, val, d in rows:
    if kind == "info":
        continue
    raw, _ = P.claims_padded(val, kind)
    ok = block_ok(d, raw[:len(raw) - (len(raw) % 4 and 0)])  # padded[:len]
    # claims_padded returns (padded, unpadded_len); use unpadded slice
    padded, ulen = P.claims_padded(val, kind)
    ok = block_ok(d, padded[:ulen])
    calib_ok &= ok
    print("  %-24s %s" % (label, "MATCH" if ok else "fail"))
print("calibration:", "ALL OK" if calib_ok else "BROKEN")
print()

# ------------------------------------------------------- info: PIN splits
INFO_KEYS = ["adj_verification", "android_uuid", "app_token", "created_at",
             "environment", "gps_adid", "gps_adid_src", "push_token",
             "source", "tracking_enabled"]
info_rows = [(l, v, d) for l, k, v, d in rows if k == "info"]

print("== info: PIN split search over the mapget-proven key list ==")
print("   keys:", INFO_KEYS)
print()
V = lambda val, ks: "".join(val[k] for k in ks)


def block2(val):
    return (val["activity_kind"] + val["client_sdk"] + val["headers_id"]
            + val["native_version"])


hits = {}
for split in range(0, 11):
    for use_pin in (True, False):
        name = "split@%d%s" % (split, "+PIN" if use_pin else "+noPIN")
        per = []
        for label, val, d in info_rows:
            head_vals = INFO_KEYS[:split]
            tail_vals = INFO_KEYS[split:]
            parts = V(val, head_vals)
            if use_pin:
                parts += val["adj_signing_id"]
            parts += V(val, tail_vals) + block2(val)
            per.append(block_ok(d, parts))
        hits[name] = per
        mark = "".join("Y" if x else "." for x in per)
        print("  %-16s %s" % (name, mark))

print()
winners = [n for n, per in hits.items() if all(per)]
print("WINNERS (all rows):", winners or "none")
part = [n for n, per in hits.items() if any(per)]
print("partial:", part or "none")

# show winning claims length
for w in winners:
    split = int(w.split("@")[1].split("+")[0])
    label, val, d = info_rows[0]
    parts = V(val, INFO_KEYS[:split]) + val["adj_signing_id"] \
        + V(val, INFO_KEYS[split:]) + block2(val)
    print("  %s -> claims %d bytes" % (w, len(parts)))
    print("  claims:", parts)
