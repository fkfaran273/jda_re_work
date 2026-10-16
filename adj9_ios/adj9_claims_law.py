# -*- coding: utf-8 -*-
"""adj9cl_law.py — the SOLVED adj9 iOS claims-construction law (SDK 5.8.0 /
signature native 5.0.0), verified byte-exact against the captured penti-iOS
records, plus the BLOCK pre-image assembly.

Law (values only, bare concatenation, latin-1):

  signing map = wire params (percent-DECODED values)
              + core-injected { adj_verification, adj_signing_id="1500000",
                activity_kind ("session"|"click"|"attribution"),
                client_sdk="ios5.8.0", headers_id="10",
                native_version="5.0.0" }

  claims = adj_verification
        || profile: 95-key core pool keys < "session_count" present in map,
           pool (alphabetical) order
        || "1500000"                       (adj_signing_id, pinned)
        || tail:    pool keys >= "session_count" present in map, pool order
        || activity_kind, client_sdk, headers_id, native_version

  (the 95-key pool: adj9_pool_order.json minus activity_kind/client_sdk;
   non-pool wire keys — sent_at, needs_response_details, attribution_deeplink,
   foreground/background, enqueue_size, retry_count, offline_mode_enabled,
   send_in_background_enabled — are NOT claimed)

BLOCK pre-image (Android-proven recipe, iOS fields):

  msg   = D9 || 00 08 || head16 || LE32(S) || sha256("") || TAIL || claims
  D9    = record[25:45]   (20 zero bytes on iOS)
  head16= record[3:19]    (the record's INTERNAL head — not the blob header)
  S     = BE32(record[20:24])
  TAIL  = record[112] || record[114:130]  =  02 || 'iPhone12,1' || 00*6  (17 B)
          (the exact Android BLOCK_TAIL law: middle byte + 16-B desc-7 value)
  BLOCK = sha256 with custom IV2 (adj9_signer.sha256_iv2), standard padding

Verification vs the 5 unsealed penti-iOS records: rec0 session, rec1 click,
rec2 attribution(backend), rec4 attribution(sdk) — byte-exact 4/4.  rec3
(the single background push-retry attribution) does not reproduce; see
ADJ9IOS_CLAIMS_LAW.md section 5 for the exclusion set run against it.
"""
import sys, json, struct

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\one_click_run")
import adj9_signer as sg

WORK = r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios"

POOL_95 = [k for k in json.load(open(WORK + r"\adj9_pool_order.json"))
           if k not in ("activity_kind", "client_sdk")]
SPLIT = POOL_95.index("session_count")

INJECTED = {
    "adj_signing_id": "1500000",
    "client_sdk": "ios5.8.0",
    "headers_id": "10",
    "native_version": "5.0.0",
}
BLOCK2 = ["activity_kind", "client_sdk", "headers_id", "native_version"]


def signing_map(wire_params, activity_kind, adj_verification):
    m = dict(wire_params)
    m["adj_signing_id"] = INJECTED["adj_signing_id"]
    m["client_sdk"] = INJECTED["client_sdk"]
    m["headers_id"] = INJECTED["headers_id"]
    m["native_version"] = INJECTED["native_version"]
    m["activity_kind"] = activity_kind
    m["adj_verification"] = adj_verification
    return m


def build_claims(wire_params, activity_kind, adj_verification):
    """The claims string (str) for one request."""
    m = signing_map(wire_params, activity_kind, adj_verification)
    prof = [k for k in POOL_95[:SPLIT] if m.get(k)]
    tail = [k for k in POOL_95[SPLIT:] if m.get(k)]
    keys = (["adj_verification"] + prof + ["adj_signing_id"] + tail + BLOCK2)
    return "".join(m[k] for k in keys), keys


def block_message(record, claims):
    """BLOCK pre-image from the unsealed 144-B record + claims (bytes/str)."""
    if isinstance(claims, str):
        claims = claims.encode("latin-1")
    return (record[25:45] + b"\x00\x08" + record[3:19]
            + record[20:24][::-1]                     # BE32 storage -> LE32 in msg
            + sg.SHA0 + record[112:113] + record[114:130] + claims)


def predict_block(record, claims):
    return sg.sha256_iv2(block_message(record, claims))


def verify(records, bodies_by_second, adj_verification, verbose=True):
    """records: _penti_records.json list; bodies: sent_at-sorted wire dicts."""
    ok = {}
    for rec, (params, order) in zip(records, bodies_by_second):
        kind = {0: "session", 1: "click"}.get(rec["i"], "attribution")
        claims, keys = build_claims(params, kind, adj_verification)
        rec_b = bytes.fromhex(rec["record"])
        got = predict_block(rec_b, claims)
        ok[rec["i"]] = (got == rec_b[46:78])
        if verbose:
            print("rec[%d] %-11s second=%d  claims=%3d B  block %s"
                  % (rec["i"], kind, rec["second"], len(claims),
                     "MATCH" if ok[rec["i"]] else "no match"))
    return ok


if __name__ == "__main__":
    sys.path.insert(0, WORK)
    from adj9cl_search import load_bodies
    recs = json.load(open(WORK + r"\_penti_records.json"))
    bodies = load_bodies()
    REQS = [bodies[s] for s in sorted(bodies)]
    AV = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"
    res = verify(recs, REQS, AV)
    print("\nsummary:", res)
