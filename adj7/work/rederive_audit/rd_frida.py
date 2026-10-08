"""Ground-truth test on the FRIDA sign_calls: (arg1+arg2 map) -> genuine blob.
Decrypt each genuine blob, recover H/nonce/cert, then test build_claims."""
import json, os, sys

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj7_pure as ap
from rd_core import H_of, cbc_decrypt, parse_record
import hashlib, hmac

HERE = os.path.dirname(os.path.abspath(__file__))
m = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\hanaf_map.json"))

for sc in m["sign_calls"]:
    import re
    a3 = sc.get("arg3_after") or {}
    # FRIDA split the auth header across map keys at '", "' chunk boundaries:
    # reassemble by stripping escapes and the split seams, then grab 608 hex.
    raw3 = json.dumps(a3).replace('\\"', '"').replace('", "', '')
    am = re.search(r'signature="([0-9A-Fa-f]{608})"', raw3)
    if not am:
        print("n=%d %s: no authorization captured" % (sc["n"], sc.get("kind_hint")))
        continue
    blob = bytes.fromhex(am.group(1))
    header, body, tag = blob[:16], blob[16:272], blob[272:304]
    tag_ok = hmac.new(ap.DK37, body, hashlib.sha256).digest() == tag
    pt = cbc_decrypt(body, header)
    reenc = ap.cbc_encrypt(pt, header) == body
    info = parse_record(pt)
    nonce12 = int(info["A"].decode()).to_bytes(8, "little") + bytes.fromhex(info["d8"].decode())
    cert40 = info["cert40"]
    Hd = info["H"]
    arg2 = sc["arg2"]
    merged = dict(sc["arg1"]); merged.update(arg2)
    kind = arg2["activity_kind"]
    csdk = arg2["client_sdk"]

    results = {}
    # candidate A: current law
    claimsA = ap.build_claims(kind, merged, client_sdk=csdk, include_block2=True)
    results["A current law (merged, block2)"] = claimsA
    # candidate B: arg1 only + block2 defaults
    claimsB = ap.build_claims(kind, dict(sc["arg1"]), client_sdk=csdk, include_block2=True)
    results["B arg1 only, block2"] = claimsB
    # candidate C: merged, no block2 (activity_kind/client_sdk only if in arg1)
    claimsC = ap.build_claims(kind, merged, client_sdk=csdk, include_block2=False)
    results["C merged, no block2"] = claimsC

    print("n=%d %s  tag_ok=%s reenc=%s tmpl=%s  Hd=%s..." %
          (sc["n"], sc.get("kind_hint"), tag_ok, reenc, info["ok"], Hd[:16]))
    for label, claims in results.items():
        H = H_of(claims, nonce12, cert40).hex().upper()
        print("   %-32s len=%4d  %s" % (label, len(claims), "MATCH" if H == Hd else "mismatch"))
    # dump maps for the audit file
    json.dump({"arg1": sc["arg1"], "arg2": arg2, "sig": am.group(1).upper(),
               "kind": kind},
              open(os.path.join(HERE, "frida_n%d.json" % sc["n"]), "w"), indent=1)
