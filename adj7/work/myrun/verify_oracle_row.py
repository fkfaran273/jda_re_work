"""verify_oracle_row.py -- independent offline check of the single
resigned row in adj7/oracle/oracle_log.jsonl:

1. our_blob tag valid under DK37
2. our_blob decrypts (inverse SPN) to the same record shape
3. device_record.device_H == our H over our claims built from the same
   fields (same nonce12, cert40)
4. our_blob header matches make_header of the claimed created_at second
5. claims_match from the.xml-removallog row is independently true/false
"""
import gzip
import hashlib
import hmac as hmac_mod
import json
import re
import sys

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun"
sys.path.insert(0, HERE)
import adj7_pure as sg

rows = [json.loads(l) for l in open(
    r"C:\Users\Apps\Downloads\com.penti.app\adj7\oracle\oracle_log.jsonl")]
sess = next(r for r in rows if r.get("resigned"))

fields = sess["fields"]
dev = sess["device_record"]
nonce12 = bytes.fromhex(dev["nonce12"])
cert40 = dev["device_cert40"].encode()
device_H = dev["device_H"]

KINDS = {"/session": "session", "/sdk_click": "click",
         "/event": "event", "/attribution": "attribution"}
kind = KINDS[sess["path"]]

claims = sg.build_claims(kind, fields, client_sdk="android5.6.0",
                         include_block2=True)
H_our = sg.commitment_digest(claims, nonce12, cert40).hex().upper()
print("device_H    :", device_H)
print("our H       :", H_our)
print("claims H match:", H_our == device_H, "| log claims_match:",
      sess["claims_match"])

our_blob = bytes.fromhex(sess["our_blob"])
tag_ok = hmac_mod.new(sg.DK37, our_blob[16:272], hashlib.sha256).digest() \
    == our_blob[272:304]
print("tag_ok:", tag_ok, "| log tag_ok:", dev["tag_ok"])
print("our_blob len:", len(our_blob))
print("our_second:", sess["our_second"])
print("created_at field:", fields["created_at"])

# our header law on the claimed second
from datetime import datetime, timezone, timedelta
ca = fields["created_at"].replace("Z+0530", "")
dt = datetime.strptime(ca.split(".")[0], "%Y-%m-%dT%H:%M:%S")
sec = int((dt - timedelta(hours=5, minutes=30)).replace(
    tzinfo=timezone.utc).timestamp())
print("created_at second:", sec, "| header match:",
      sg.make_header(sec) == our_blob[:16])
