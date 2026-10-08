"""dd_sig_check.py -- (c) our signature internals via parse_device_blob;
device blob decryption + claims cross-check for the hunch rows."""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADJ7 = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ADJ7)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ADJ7, "oracle"))

import run_install as ri          # noqa: E402
import adj7_pure as ap            # noqa: E402
import adj7_oracle as orc         # noqa: E402  (parse_device_blob / cbc path)

val = json.load(open(os.path.join(HERE, "dd_value_report.json"),
                     encoding="utf-8"))
our_sess, our_click, our_attr = (val["our_sess"], val["our_click"],
                                 val["our_attr"])
sec, click_sec = val["sec"], val["click_sec"]
dev_rows = json.load(open(os.path.join(HERE, "dd_wire_requests.json"),
                          encoding="utf-8"))
dev_sess_w = dict(dev_rows[142]["body_pairs"])
dev_click_w = dict(dev_rows[143]["body_pairs"])
dev_attr_w = dict(dev_rows[144]["query_pairs"])
dev_auths = {n: dict(dev_rows[i]["headers"])["Authorization"]
             for n, i in (("session", 142), ("click", 143),
                          ("attribution", 144))}

print("========== (c) OUR signature internals ==========")
for name, fields, s in (("session", our_sess, sec),
                        ("click", our_click, sec),
                        ("attribution", our_attr, sec)):
    auth = ri.sign(fields, name, s)
    blob_hex = re.search(r'signature="([0-9A-F]+)"', auth).group(1)
    blob = bytes.fromhex(blob_hex)
    rec = orc.parse_device_blob(auth)
    print("\n-- %s --" % name)
    print("  auth fmt ok:",
          re.match(r'^Signature signature="[0-9A-F]{608}",'
                   r'adj_signing_id="1300000",algorithm="adj7",'
                   r'headers_id="8",native_version="3\.62\.0"$', auth)
          is not None)
    print("  blob len:", len(blob), " tag_ok:", rec.get("tag_ok"))
    print("  nonce_a  :", rec.get("nonce_a"), "(20ch right-justified:",
          len(rec.get("nonce_a", "")) <= 20, ")")
    print("  device_H :", rec.get("device_H"))
    print("  cert40   :", rec.get("device_cert40"),
          "== campaign:", rec.get("device_cert40")
          == ri.CAMPAIGN["cert_sha1"].upper())
    print("  d8       :", rec.get("device_d8"))
    n12 = bytes.fromhex(rec["nonce12"])
    print("  nonce12  :", rec["nonce12"], " distinct bytes:",
          len(set(n12)), "/12")
    # header == make_header(created_at second)?
    import datetime as dt
    ca = fields["created_at"]
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", ca)
    Y, Mo, D, h, mi, se = map(int, m.groups())
    # our stamps are local-wallclock+Z offset; the real second:
    off = 5 * 3600 + 30 * 60
    real_sec = int(dt.datetime(Y, Mo, D, h, mi, se,
                               tzinfo=dt.timezone.utc).timestamp()) - off
    hdr = blob[:16]
    exp = ap.make_header(real_sec)
    print("  created_at second: %d  signing second arg: %d  equal: %s"
          % (real_sec, s, real_sec == s))
    print("  header == make_header(created_at sec):", hdr == exp,
          " hex:", hdr.hex())
    # claims: recompute with include_block2 (the runner path)
    claims = ap.build_claims(name, fields,
                             client_sdk=ri.CAMPAIGN["client_sdk"],
                             include_block2=True)
    H = ap.commitment_digest(claims, n12, rec["device_cert40"].encode())
    print("  H recompute over our claims:", H.hex().upper()
          == rec["device_H"])

print()
print("========== DEVICE blobs (hunch rows) ==========")
for name, fields in (("session", dev_sess_w), ("click", dev_click_w),
                     ("attribution", dev_attr_w)):
    auth = dev_auths[name]
    rec = orc.parse_device_blob(auth)
    blob = bytes.fromhex(re.search(r'signature="([0-9A-F]+)"',
                                   auth).group(1))
    print("\n-- device %s --" % name)
    print("  tag_ok:", rec.get("tag_ok"), " cert40:",
          rec.get("device_cert40"), "== campaign:",
          rec.get("device_cert40") == ri.CAMPAIGN["cert_sha1"].upper())
    ca = fields["created_at"]
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", ca)
    Y, Mo, D, h, mi, se = map(int, m.groups())
    real_sec = int(dt.datetime(Y, Mo, D, h, mi, se,
                               tzinfo=dt.timezone.utc).timestamp()) \
        if False else None
    # device stamps are +0530 local; decode to epoch
    off = 5 * 3600 + 30 * 60
    real_sec = int(dt.datetime(Y, Mo, D, h, mi, se,
                               tzinfo=dt.timezone.utc).timestamp()) - off
    hdr, exp = blob[:16], ap.make_header(real_sec)
    print("  header == make_header(created_at sec):", hdr == exp)
    n12 = bytes.fromhex(rec["nonce12"])
    # claims over the DEVICE's wire fields, our builder, flutter sdk
    sdk = "flutter5.5.0@android5.5.0"
    variants = {
        "block2(client_sdk)": ap.build_claims(
            name, fields, client_sdk=sdk, include_block2=True),
    }
    if name == "attribution":
        f2 = dict(fields); f2["language"] = "en"
        variants["block2+language"] = ap.build_claims(
            name, f2, client_sdk=sdk, include_block2=True)
        variants["no-block2"] = ap.build_claims(
            name, fields, client_sdk=sdk, include_block2=False)
    if name == "session":
        f2 = dict(fields); f2["partner_params"] = "{}"
        variants["block2+pp"] = ap.build_claims(
            name, f2, client_sdk=sdk, include_block2=True)
    for vn, claims in variants.items():
        H = ap.commitment_digest(claims, n12,
                                 rec["device_cert40"].encode())
        print("  claims %-22s H match: %s" % (
            vn, H.hex().upper() == rec["device_H"]))
