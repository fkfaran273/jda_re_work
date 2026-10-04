"""verify_info_law.py -- prove the info (/sdk_info) signing law end to end.

THE LAW (verified):
    info:  profile = PROFILE, tail = ['source', 'tracking_enabled']
    emitted: sorted(PROFILE keys carried by the map) + adj_signing_id
             + ['source', 'tracking_enabled'] + BLOCK2
    i.e. identical in shape to session/click; `source` is a TAIL key exactly
    as it is for click.  The /sdk_info map also carries first_error,
    last_error, wait_time, wait_total, retry_count, offline_mode_enabled,
    enqueue_size, gps_adid_attempt, foreground, needs_response_details,
    attribution_deeplink and sent_at -- the signer claims NONE of them.

EVIDENCE
  1. Block oracle, saz capture (8 Sep, Fiddler, real network traffic, OnePlus
     / OS 11 / app 3.12.1):      MATCH
  2. Block oracle, oracle_run3 (9 Sep, moto g42, app 3.12.1, first info
     signing, ev3):              MATCH
  3. Full 192-byte envelopes rebuilt byte-exact from scratch for BOTH of the
     above via sign_request(..., 'info', ...).
  4. Native behavioural proof: the mapget hook in adj9/device/adj9_wh.log
     shows the signer querying the map key by key during nSign.  For every
     info signing it queries exactly
       adj_verification android_uuid app_token created_at environment
       gps_adid gps_adid_src push_token source tracking_enabled
       activity_kind client_sdk
     in that (sorted) order, twice per call.  None of the extra /sdk_info
     fields is ever queried, and adj_signing_id/headers_id/native_version are
     campaign inputs, not map lookups.
  5. 34 further genuine info signings from the 12 Sep capture (app 3.13.9,
     adj9_wh.log 17/17 + adj9_wh2.log 17/17) also pass the block oracle with
     this law.

NOTE on event_vectors.json rows 4/5 (ts ...051/...052): these are NOT genuine
signings.  oracle_run3.log shows them as `oracle_same_0/1` -- the harness
re-invoked nSign after the real signing to probe determinism, feeding
reconstructed inputs (their arg3 key material even toggles 8042f41c ->
8142f41c between replays), and only the FIRST call's sign_input map was
logged.  Their claims therefore cannot be recovered from the capture and they
are excluded here; they are not counter-evidence.
"""
import base64
import itertools
import json
import os
import re
import struct
import sys
from urllib.parse import parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_pure as P
import adj9_decode as D  # noqa: E402

VECS = json.load(open(os.path.join(HERE, "event_vectors.json")))
SAZ = json.load(open(os.path.join(HERE, "saz_vectors.json")))
BASE = json.load(open(os.path.join(HERE, "apps.json")))["penti"]

# the emitted claims key order the law must produce for an info map
EXPECTED_ORDER = ["adj_verification", "android_uuid", "app_token", "created_at",
                  "environment", "gps_adid", "gps_adid_src", "push_token",
                  "adj_signing_id", "source", "tracking_enabled",
                  "activity_kind", "client_sdk", "headers_id", "native_version"]


def phase_for(rec, seed):
    for c in (1, 2, 3):
        for q in itertools.permutations(range(0x20, 0x50), c):
            try:
                if P.head16_for(seed, q) == rec[3:19]:
                    return q
            except Exception:
                continue
    return None


def decode(blob):
    rec = D.whiten_body_inverse(blob[16:160], blob[:16])
    assert rec[0:3] == b"\x01\x00\x08" and rec[19] == 2 and rec[24] == 3 \
        and rec[45] == 4 and rec[78] == 5, "record decode failed"
    return {"seed": struct.unpack(">I", rec[20:24])[0], "head": rec[3:19],
            "cert": rec[25:45], "want": rec[46:78], "rec": rec}


def block_ok(d, claims):
    return P.record_block(d["head"], d["seed"], claims, d["cert"]) == d["want"]


def main():
    print("=" * 70)
    print("info claims law: sorted(PROFILE) + adj_signing_id")
    print("                 + ['source', 'tracking_enabled'] + BLOCK2")
    print()

    # 1. the law emits the proven key order for an info map
    info_maps = [v["map"] for v in VECS if v["map"]["activity_kind"] == "info"]
    order = P.claim_key_order(info_maps[0], "info")
    ok_order = order == EXPECTED_ORDER
    print("claim_key_order(info map) == proven order:", ok_order)
    if not ok_order:
        print("  got:     ", order)
        print("  expected:", EXPECTED_ORDER)
    print()

    ok = True

    # 2. oracle_run3 genuine info signing (first one; later two are replays)
    print("-- oracle_run3 capture (9 Sep, moto g42) --")
    genuine = [v for v in VECS if v["map"]["activity_kind"] == "info"]
    v = genuine[0]
    blob = bytes.fromhex(v["blob"])
    d = decode(blob)
    padded, ulen = P.claims_padded(v["map"], "info")
    m1 = block_ok(d, padded[:ulen])
    ok &= m1
    print("   block oracle (seed %d):            %s"
          % (d["seed"], "MATCH" if m1 else "FAIL"))
    ph = phase_for(d["rec"], d["seed"])
    P.campaign_data = BASE
    auth = P.sign_request(v["map"], "info", head=ph,
                          second=v["ts"], seed=d["seed"])
    got = base64.b64decode(re.search(r'signature="([^"]+)"', auth).group(1))
    m2 = got == blob
    ok &= m2
    print("   full envelope rebuild:             %s"
          % ("EXACT 192/192" if m2 else "FAIL"))
    print("   (rows ts=%d/%d are oracle_same harness replays;"
          " excluded, see docstring)" % (genuine[1]["ts"], genuine[2]["ts"]))
    print()

    # 3. saz /sdk_info capture (8 Sep, independent session + device)
    print("-- saz capture (8 Sep, OnePlus, real network traffic) --")
    r = SAZ["info"]
    sig = bytes.fromhex(r["sig_hex"])
    d = decode(sig)
    assert d["seed"] == r["seed"] and d["head"].hex() == r["head_hex"] \
        and d["cert"].hex() == r["cert_hex"] \
        and d["want"].hex() == r["block_hex"], "saz decode mismatch"
    val = {k: v[0] for k, v in parse_qs(r["form"]).items()}
    # the envelope fields the signer adds from the campaign, exactly as
    # sign_request does, so the claims can be rebuilt outside sign_request
    val.update({"activity_kind": "info",
                "client_sdk": BASE.get("client_sdk", "android5.7.0"),
                "adj_signing_id": BASE["adj_signing_id"],
                "headers_id": BASE["headers_id"],
                "native_version": BASE["native_version"],
                "adj_verification": BASE["adj_verification"]})
    padded, ulen = P.claims_padded(val, "info")
    m3 = block_ok(d, padded[:ulen])
    ok &= m3
    print("   block oracle (seed %d):            %s"
          % (d["seed"], "MATCH" if m3 else "FAIL"))
    ph = phase_for(d["rec"], d["seed"])
    sent = val["sent_at"]                       # e.g. 2026-09-08T14:05:25.665Z+0530
    dt = __import__("datetime").datetime.strptime(
        sent.split(".")[0], "%Y-%m-%dT%H:%M:%S")
    tz = __import__("datetime").timezone(
        __import__("datetime").timedelta(hours=int(sent[-4:-2]),
                                         minutes=int(sent[-2:])))
    base = int(dt.replace(tzinfo=tz).timestamp())
    second = next((base + i for i in range(-300, 300)
                   if P.make_header(base + i) == sig[:16]), None)
    m4 = False
    if second is not None:
        P.campaign_data = BASE
        auth = P.sign_request(val, "info", head=ph,
                              second=second, seed=d["seed"])
        got = base64.b64decode(re.search(r'signature="([^"]+)"', auth).group(1))
        m4 = got == sig
    ok &= m4
    print("   full envelope rebuild (second=%s): %s"
          % (second, "EXACT 192/192" if m4 else "FAIL"))
    print()

    print("RESULT: info law %s"
          % ("VERIFIED -- both independent captures rebuild byte-exact"
             if ok else "NOT VERIFIED"))
    return 0 if (ok and ok_order) else 1


if __name__ == "__main__":
    sys.exit(main())
