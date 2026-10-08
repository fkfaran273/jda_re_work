"""runner part of rd_verify (crypto core lives in rd_core)"""
import json, os, sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rd_core import *

# ---------------- run over rows ----------------------------------------
rows = json.load(open(os.path.join(os.path.dirname(__file__), "rows_fresh.json")))
report = []
for i, r in enumerate(rows):
    blob = bytes.fromhex(r["sig"])
    rec = {"row": i, "src": r["src"] + ":" + r["label"], "path": r["path"],
           "kind_path": r["kind_path"], "csdk": r["client_sdk_header"],
           "blob_len": len(blob)}
    if len(blob) != 304:
        rec["error"] = "blob len %d" % len(blob)
        report.append(rec); continue
    header, body, tag = blob[:16], blob[16:272], blob[272:304]
    rec["tag_ok"] = hmac.new(DK37, body, hashlib.sha256).digest() == tag
    pt = cbc_decrypt(body, header)
    rec["reencrypt_ok"] = (ap.cbc_encrypt(pt, header) == body)   # AES core check
    info = parse_record(pt)
    rec["record_template_ok"] = info["ok"]
    rec["template_detail"] = {k: v for k, v in info.items() if k.startswith("ok_") or not info["ok"]}
    try:
        nonce12 = int(info["A"].decode()).to_bytes(8, "little") + bytes.fromhex(info["d8"].decode())
        rec["nonce12"] = nonce12.hex().upper()
        rec["cert40"] = info["cert40"].hex()
        rec["cert40_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in info["cert40"])
        rec["H"] = info["H"].hex().upper()
        rec["e_ok"] = (info["e"] == ap.SHA0_HEX.encode())
        rec["_nonce"] = nonce12.hex()
        rec["_cert"] = info["cert40"]
        rec["_H"] = info["H"]
    except Exception as ex:
        rec["error"] = "record parse: %r" % ex
    report.append(rec)

json.dump(report, open(os.path.join(os.path.dirname(__file__), "crypto_report.json"), "w"),
          indent=1, default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o))

print(f'{"row":>3} {"tag":^5} {"reenc":^5} {"tmpl":^5} {"e":^5} cert40            nonce12           path')
for rec in report:
    if "error" in rec:
        print(rec["row"], "ERROR", rec["error"]); continue
    print(f'{rec["row"]:>3} {str(rec["tag_ok"]):^5} {str(rec["reencrypt_ok"]):^5} '
          f'{str(rec["record_template_ok"]):^5} {str(rec.get("e_ok")):^5} {rec.get("cert40_ascii","?"):<18} '
          f'{rec.get("nonce12","?"):<16} {rec["path"]}  [{rec["kind_path"]}]')
