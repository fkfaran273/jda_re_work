"""Full brute matrix against the FRIDA ground-truth (arg1+arg2 -> genuine blob)."""
import json, os, sys, re

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj7_pure as ap
from rd_core import H_of, cbc_decrypt, parse_record
import hashlib, hmac

HERE = os.path.dirname(os.path.abspath(__file__))
m = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\hanaf_map.json"))
POOL = list(ap.CLAIM_POOL)
SIGID = ap.ADJ_SIGNING_ID

def blob_record(sig):
    blob = bytes.fromhex(sig)
    header, body = blob[:16], blob[16:272]
    pt = cbc_decrypt(body, header)
    info = parse_record(pt)
    nonce12 = int(info["A"].decode()).to_bytes(8, "little") + bytes.fromhex(info["d8"].decode())
    return nonce12, info["cert40"], info["H"]

def build(fields, sigid_pos, split_at, skip_empty, extra_order=None):
    mm = dict(fields)
    split = {"seq": POOL.index("seq"), "session_count": POOL.index("session_count"),
             "none": len(POOL)}[split_at]
    profile, tail = POOL[:split], POOL[split:]
    b2 = [k for k in ("activity_kind", "client_sdk") if k in tail]
    tail = [k for k in tail if k not in ("activity_kind", "client_sdk")]
    def val(k):
        v = mm.get(k)
        if v is None: return None
        if skip_empty and v == "": return None
        return str(v)
    parts = []
    for k in profile:
        v = val(k)
        if v is not None: parts.append(v)
    if sigid_pos == "profile_tail": parts.append(SIGID)
    for k in tail:
        v = val(k)
        if v is not None: parts.append(v)
    if sigid_pos == "tail_block2": parts.append(SIGID)
    for k in b2:
        v = val(k)
        if v is not None: parts.append(v)
    if sigid_pos == "end": parts.append(SIGID)
    return "".join(parts).encode("latin1")

for sc in m["sign_calls"]:
    a3 = sc.get("arg3_after") or {}
    raw3 = json.dumps(a3).replace('\\"', '"').replace('", "', '')
    am = re.search(r'signature="([0-9A-Fa-f]{608})"', raw3)
    if not am: continue
    sig = am.group(1).upper()
    nonce12, cert40, Hd = blob_record(sig)
    kind = sc["arg2"]["activity_kind"]; csdk = sc["arg2"]["client_sdk"]
    merged = dict(sc["arg1"]); merged.update(sc["arg2"])
    print("== n=%d %s  Hd=%s..." % (sc["n"], kind, Hd[:16]))
    hits = []
    # base configs x single-key drops
    for sigid_pos in ("profile_tail", "absent", "tail_block2", "end"):
        for split_at in ("seq", "session_count"):
            for skip_empty in (True, False):
                base = build(merged, sigid_pos, split_at, skip_empty)
                if H_of(base, nonce12, cert40).hex().upper() == Hd:
                    hits.append(("base", sigid_pos, split_at, skip_empty))
                for dk in list(merged):
                    f2 = {k: v for k, v in merged.items() if k != dk}
                    c2 = build(f2, sigid_pos, split_at, skip_empty)
                    if H_of(c2, nonce12, cert40).hex().upper() == Hd:
                        hits.append(("drop:" + dk, sigid_pos, split_at, skip_empty))
    # single-key ADDS: pool keys absent, plausible values
    sibs = {}
    for r in json.load(open(os.path.join(HERE, "rows_fresh.json"))):
        for k, v in r["fields"].items():
            sibs.setdefault(k, set()).add(v)
    for pk in POOL:
        if pk in merged: continue
        vals = set(sibs.get(pk, set())) | {"0", "1", ""}
        for v in list(vals)[:6]:
            f2 = dict(merged); f2[pk] = v
            for sigid_pos in ("profile_tail",):
                for split_at in ("seq", "session_count"):
                    c2 = build(f2, sigid_pos, split_at, True)
                    if H_of(c2, nonce12, cert40).hex().upper() == Hd:
                        hits.append(("add:%s=%s" % (pk, v), sigid_pos, split_at, True))
    print("   hits:", hits if hits else "NONE")
