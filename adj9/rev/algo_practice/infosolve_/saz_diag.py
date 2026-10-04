"""saz_diag.py -- find why the saz session/click rows miss the block oracle
while the same law matches the oracle_run3 rows and the saz attribution row.

Scans: drop each emitted key; add each unemitted body key (profile and tail
positions); envelope variants.
"""
import json
import os
import struct
import sys
from urllib.parse import parse_qs

MRUN = r"C:\Users\Apps\Downloads\com.penti.app\manual_run"
sys.path.insert(0, MRUN)
import adj9_pure as P          # noqa: E402
import adj9_decode as D        # noqa: E402

APPS = json.load(open(os.path.join(MRUN, "apps.json")))["penti"]

saz = json.load(open(os.path.join(MRUN, "saz_vectors.json")))


def row_for(kind):
    r = saz[kind]
    blob = bytes.fromhex(r["sig_hex"])
    rec = D.whiten_body_inverse(blob[16:160], blob[:16])
    val = {k: v[0] for k, v in parse_qs(r["form"]).items()}
    if not r["form"]:
        val = {k: v[0] for k, v in parse_qs(r["path"].split("?", 1)[1]).items()}
    val.setdefault("activity_kind", kind)
    val.setdefault("client_sdk", APPS["client_sdk"])
    val.setdefault("adj_verification", APPS["adj_verification"])
    val.setdefault("adj_signing_id", APPS["adj_signing_id"])
    val.setdefault("headers_id", APPS["headers_id"])
    val.setdefault("native_version", APPS["native_version"])
    return {"seed": struct.unpack(">I", rec[20:24])[0], "head": rec[3:19],
            "cert": rec[25:45], "want": rec[46:78], "val": val}


def ok(d, claims):
    return P.record_block(d["head"], d["seed"], claims, d["cert"]) == d["want"]


def emit_keys(val, kind):
    prof, tail = P._GROUPS[kind]
    return ([k for k in sorted(prof) if val.get(k)], P.PIN,
            [k for k in sorted(tail) if val.get(k)])


def claims_from(val, kind, prof=None, pin=True, tail=None):
    p, _, t = emit_keys(val, kind)
    prof = p if prof is None else prof
    tail = t if tail is None else tail
    s = "".join(val[k] for k in prof)
    if pin:
        s += val["adj_signing_id"]
    s += "".join(val[k] for k in tail)
    s += "".join(val[k] for k in P.BLOCK2 if val.get(k))
    return s.encode("latin1")


for kind in ("session", "click"):
    d = row_for(kind)
    val = d["val"]
    base = claims_from(val, kind)
    print("== saz:%s  base %d bytes -> %s"
          % (kind, len(base), "MATCH" if ok(d, base) else "MISS"))
    prof, _, tail = emit_keys(val, kind)
    emitted = prof + tail
    body_keys = [k for k in val if k not in prof + tail
                 and k not in ("adj_signing_id", "headers_id",
                               "native_version", "adj_verification",
                               "client_sdk", "activity_kind")]
    # 1. drop each emitted key
    for k in emitted:
        p2 = [x for x in prof if x != k]
        t2 = [x for x in tail if x != k]
        if ok(d, claims_from(val, kind, p2, True, t2)):
            print("   MATCH dropping %s" % k)
    # 2. add each unemitted body key (either group)
    for k in body_keys:
        for grp, lst in (("prof", prof), ("tail", tail)):
            p2, t2 = list(prof), list(tail)
            if grp == "prof":
                p2 = sorted(p2 + [k])
            else:
                t2 = sorted(t2 + [k])
            if ok(d, claims_from(val, kind, p2, True, t2)):
                print("   MATCH adding %s to %s" % (k, grp))
    # 3. no-PIN variant
    if ok(d, claims_from(val, kind, prof, False, tail)):
        print("   MATCH without PIN")
    # 4. envelope value variants
    for alt in ("", "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"):
        v2 = dict(val)
        if alt:
            v2["adj_verification"] = alt
        else:
            v2.pop("adj_verification")
        p, _, t = emit_keys(v2, kind)
        if ok(d, claims_from(v2, kind, p, True, t)):
            print("   MATCH with adj_verification=%r" % alt)
print("scan done")
