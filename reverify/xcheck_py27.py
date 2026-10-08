"""py2.7 cross-check: mint the genuine capture vectors with
adj7_pure_py27.py and compare the Authorization string byte-for-byte.
Run:  py -2.7 xcheck_py27.py
"""
import json
import sys

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\reverify")

import adj7_pure_py27 as ap

rows = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app"
                      r"\reverify\xcheck_py27_input.json"))
ok = True
for r in rows:
    nonce = r["nonce12"].decode("hex")
    auth = ap.mint_adj7(r["kind"], r["fields"], unix_sec=r["second"],
                        include_block2=True, nonce12=nonce,
                        campaign=r["campaign"])
    same = auth == r["want_auth"]
    ok = ok and same
    print("%s sid%s %s -> %s" % (r["cap"], r["sid"], r["kind"],
                                 "OK" if same else "** FAIL **"))
    if not same:
        print("  ours:", auth[:150])
        print("  want:", r["want_auth"][:150])
print("PY27 XCHECK %s" % ("OK" if ok else "FAILED"))
