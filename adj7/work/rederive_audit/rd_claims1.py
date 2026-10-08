"""Claims law test: for each row, claims = adj7_pure.build_claims(kind, fields,
client_sdk=header_client_sdk, include_block2=True) -> H vs device H."""
import json, os, sys

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj7_pure as ap
from rd_verify import H_of   # reuses independent sha256-iv0 + record data

HERE = os.path.dirname(os.path.abspath(__file__))
rows = json.load(open(os.path.join(HERE, "rows_fresh.json")))
crypto = json.load(open(os.path.join(HERE, "crypto_report.json")))

KIND = {"session": "session", "sdk_click": "click", "event": "event",
        "attribution": "attribution"}

def claims_of(fields, kind, csdk, block2=True):
    return ap.build_claims(kind, fields, client_sdk=csdk, include_block2=block2)

n_ok = 0
print(f'{"row":>3} {"kind":^11} {"H match":^8}  notes')
for i, r in enumerate(rows):
    c = crypto[i]
    if "_H" not in c:
        print(i, "no record"); continue
    nonce12 = bytes.fromhex(c["_nonce"])
    cert40 = bytes.fromhex(c["_cert"]) if isinstance(c["_cert"], str) else c["_cert"]
    Hd = c["_H"]
    kind = KIND.get(r["kind_path"], r["kind_path"])
    fields = r["fields"]
    csdk = r["client_sdk_header"]
    claims = claims_of(fields, kind, csdk, True)
    H = H_of(claims, nonce12, cert40).hex().upper()
    ok = (H == Hd)
    n_ok += ok
    notes = []
    if r["fields"].get("activity_kind"): notes.append("body activity_kind=" + r["fields"]["activity_kind"])
    if r["fields"].get("client_sdk"): notes.append("body client_sdk=" + r["fields"]["client_sdk"])
    print(f'{i:>3} {r["kind_path"]:^11} {str(ok):^8}  {" ".join(notes)}')
print("MATCHES: %d/%d" % (n_ok, len(rows)))
