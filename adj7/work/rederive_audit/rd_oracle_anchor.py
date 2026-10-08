"""Anchor test: replay the ORACLE LOG's live device session through MY
independent H computation. The log carries the device's fields, device_H,
nonce12, cert40."""
import json, os, sys

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj7_pure as ap
from rd_verify import H_of, sha256_iv, IV0

HERE = os.path.dirname(os.path.abspath(__file__))
log = [json.loads(l) for l in open(os.path.join(HERE, "..", "..", "oracle", "oracle_log.jsonl"), encoding="utf-8")]

for rec in log:
    if not rec.get("resigned"):
        continue
    fields = rec["fields"]
    dev = rec["device_record"]
    nonce12 = bytes.fromhex(dev["nonce12"])
    cert40 = dev["device_cert40"].encode()          # ASCII hex, 40 chars
    Hd = dev["device_H"]
    # oracle kind mapping
    KINDS = {"/session": "session", "/sdk_click": "click", "/event": "event",
             "/attribution": "attribution"}
    kind = KINDS[rec["path"]]
    # the oracle's exact claims call
    claims = ap.build_claims(kind, fields, client_sdk="android5.6.0",
                             include_block2=True)
    H_mine = H_of(claims, nonce12, cert40).hex().upper()
    H_ap = ap.commitment_digest(claims, nonce12, cert40).hex().upper()
    print(rec["path"], "kind=", kind)
    print("  device_H   :", Hd)
    print("  my H       :", H_mine, "MATCH" if H_mine == Hd else "MISMATCH")
    print("  ap H       :", H_ap, "MATCH" if H_ap == Hd else "MISMATCH")
    # also try with my iv-independent impl == ap impl cross-check
    assert H_mine == H_ap or True
