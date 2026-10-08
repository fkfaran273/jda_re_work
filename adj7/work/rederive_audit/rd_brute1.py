"""Brute-force the claims law against device H, fresh eyes.
Parametrized builder with knobs; test the full matrix per row."""
import json, os, sys

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj7_pure as ap
from rd_verify import H_of

HERE = os.path.dirname(os.path.abspath(__file__))
rows = json.load(open(os.path.join(HERE, "rows_fresh.json")))
crypto = json.load(open(os.path.join(HERE, "crypto_report.json")))

POOL = list(ap.CLAIM_POOL)
SIGID = ap.ADJ_SIGNING_ID

def build(fields, kind, csdk, block2, sigid_pos, split_at, skip_empty, extra=None, drop=None):
    m = dict(fields)
    if drop:
        m.pop(drop, None)
    if block2:
        m.setdefault("activity_kind", kind)
        m.setdefault("client_sdk", csdk or "")
    if split_at == "seq":
        split = POOL.index("seq")
    elif split_at == "session_count":
        split = POOL.index("session_count")
    elif split_at == "none":
        split = len(POOL)
    profile, tail = POOL[:split], POOL[split:]
    block2keys = ["activity_kind", "client_sdk"]
    tail = [k for k in tail if k not in block2keys]
    def val(k):
        v = m.get(k)
        if v is None: return None
        if skip_empty and v == "": return None
        return str(v)
    parts = []
    for k in profile:
        v = val(k)
        if v is not None: parts.append(v)
    if sigid_pos == "profile_tail":
        parts.append(SIGID)
    for k in tail:
        v = val(k)
        if v is not None: parts.append(v)
    if sigid_pos == "tail_block2":
        parts.append(SIGID)
    for k in block2keys:
        v = val(k)
        if v is not None: parts.append(v)
    if sigid_pos == "end":
        parts.append(SIGID)
    return "".join(parts).encode("latin1")

def variants(fields, csdk_hdr):
    for block2 in (True, False):
        for kind in ("session", "click", "event", "attribution", "sdk_click", ""):
            for csdk in (csdk_hdr, "", (fields.get("client_sdk") or None)):
                for sigid_pos in ("profile_tail", "absent", "tail_block2", "end"):
                    for split_at in ("seq", "session_count"):
                        for skip_empty in (True, False):
                            yield dict(kind=kind, csdk=csdk, block2=block2,
                                       sigid_pos=sigid_pos, split_at=split_at,
                                       skip_empty=skip_empty)

rows_res = []
for i, r in enumerate(rows):
    c = crypto[i]
    nonce12 = bytes.fromhex(c["_nonce"])
    cert40 = bytes.fromhex(c["_cert"]) if isinstance(c["_cert"], str) else c["_cert"]
    Hd = c["_H"]
    hits = []
    for prefix_label, prefix in (("cert", cert40), ("nul", b"\x00" * 40)):
        for v in variants(r["fields"], r["client_sdk_header"]):
            claims = build(r["fields"], v["kind"], v["csdk"], v["block2"],
                           v["sigid_pos"], v["split_at"], v["skip_empty"])
            if H_of(claims, nonce12, prefix).hex().upper() == Hd:
                hits.append((prefix_label, v))
    rows_res.append({"row": i, "src": r["src"], "path": r["path"],
                     "n_hits": len(hits),
                     "hits": [(p, h) for p, h in hits[:6]]})
    print("row %2d %s %-11s hits=%d %s" % (i, r["src"], r["kind_path"], len(hits),
          hits[0] if hits else ""))

json.dump(rows_res, open(os.path.join(HERE, "brute1.json"), "w"), indent=1, default=str)
