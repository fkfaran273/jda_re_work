"""soverify_hookparse.py -- parse the 5 SIGN blocks in hook_dump.txt
thread-aware, recover nonce12/H/cert40 from each native blob, and verify
adj7_pure (H-law + full byte-exact re-sign) against each.

Outputs soverify_hook_parsed.json.
"""
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ADJ7 = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ADJ7)
import adj7_pure as ap  # noqa: E402

DUMP = os.path.join(ADJ7, "hook_dump.txt")

lines = open(DUMP, encoding="utf-8", errors="replace").read().splitlines()

# ---- pass 1: collect events per (thread) in time order ----------------------
events = []  # (time, pid_tid, type, payload)
cur_by_tid = {}
for ln in lines:
    m = re.match(r"(\d\d-\d\d) (\d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+(\d+) I ADJ7ORACLE: (.*)", ln)
    if not m:
        continue
    ts, tid, rest = m.group(2), m.group(4), m.group(5)
    if rest.startswith("SIGN BEGIN pkg="):
        cur_by_tid[tid] = {"tid": tid, "t_begin": ts, "act": {}, "glob": {}}
        continue
    cur = cur_by_tid.get(tid)
    if cur is not None:
        if rest.startswith("ACT SIZE "):
            target = cur["act"]
            continue
        if rest.startswith("GLOB SIZE "):
            target = cur["glob"]
            continue
        if rest.startswith("OUT SIZE "):
            target = cur["out"] = {}
            continue
        m2 = re.match(r"(ACT|GLOB|OUT) \d+ ([^=]+)=(.*)", rest)
        if m2:
            cur.setdefault(m2.group(1).lower(), {})[m2.group(2)] = m2.group(3)
            continue
        if rest.startswith("SIGN END"):
            events.append(cur)
            del cur_by_tid[tid]
            continue

assert len(events) == 5, "expected 5 SIGN blocks, got %d" % len(events)

# ---- classify kinds by GLOB activity_kind -----------------------------------
for ev in events:
    ev["kind"] = ev.get("glob", {}).get("activity_kind", "?")
    ev["auth"] = ev.get("out", {}).get("authorization", "")
    m = re.search(r'signature="([0-9A-Fa-f]+)"', ev["auth"])
    ev["blob_hex"] = m.group(1) if m else None

# ---- nonce/H recovery via the oracle's inverse SPN --------------------------
sys.path.insert(0, os.path.join(ADJ7, "oracle"))
# import the parse helper without starting mitmproxy: copy the two functions
INV_SBOX = [0] * 256
for _v, _s in enumerate(ap.AES_SBOX):
    INV_SBOX[_s] = _v
_INV_MCM = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def _inv_shift_rows(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * ((r + c) % 4) + c] = b[4 * r + c]
    return bytes(out)


def _mix_columns_m(b, mat):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= ap._gmul(col[j], mat[i][j])
            out[4 * q + i] = v
    return bytes(out)


def _unspn_chunk(C, keys):
    x = bytes(a ^ b for a, b in zip(C, keys[14]))
    x = _inv_shift_rows(x)
    for r in range(13, 0, -1):
        x = bytes(INV_SBOX[v] for v in x)
        x = bytes(a ^ b for a, b in zip(x, keys[r]))
        x = _mix_columns_m(x, _INV_MCM)
        x = _inv_shift_rows(x)
    x = bytes(INV_SBOX[v] for v in x)
    return bytes(a ^ b for a, b in zip(x, keys[0]))


def cbc_decrypt(body, header):
    out, prev = b"", header
    for k in range(0, len(body), 16):
        c = body[k:k + 16]
        out += bytes(a ^ b for a, b in zip(_unspn_chunk(c, ap._RK), prev))
        prev = c
    return out


def parse_blob(blob_hex):
    blob = bytes.fromhex(blob_hex)
    assert len(blob) == 304, len(blob)
    rec = cbc_decrypt(blob[16:272], blob[:16])
    s = rec.split(b"\x00")[0].decode("latin1", "replace")
    a = re.search(r'"a":\s*(\d+)', s).group(1)
    b = re.search(r'"b":\s*"([0-9A-Fa-f]{64})"', s).group(1)
    c = re.search(r'"c":\s*"([^"]*)"', s).group(1)
    d = re.search(r'"d":\s*"([^"]*)"', s).group(1)
    e = re.search(r'"e":\s*"([^"]*)"', s).group(1)
    nonce12 = int(a).to_bytes(8, "little") + bytes.fromhex(d)
    return dict(tag_ok=ap.verify_tag(blob), record=s, a=a, H=b, cert40=c,
                d8=d, e=e, nonce12_hex=nonce12.hex(), blob=blob)


# ---- the signing second: from created_at in the ACT map ----------------------
def sec_of(ts):
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)Z([+-])(\d{2})(\d{2})", ts)
    Y, Mo, Dd, h, mi, s, ms, sg, oh, om = m.groups()
    dt = datetime(int(Y), int(Mo), int(Dd), int(h), int(mi), int(s),
                  tzinfo=timezone.utc)
    off = timedelta(hours=int(oh), minutes=int(om))
    return int((dt - off if sg == "+" else dt + off).timestamp())


HANAF_CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
CLIENT_SDK = "android5.6.0"

out_rows = []
for i, ev in enumerate(events):
    blob = parse_blob(ev["blob_hex"])
    act = {k: v for k, v in ev["act"].items() if k != "SIZE 47"
           and not k.startswith("SIZE ")}
    # signed map = ACT + GLOB (endpoint/client_sdk/activity_kind), minus SIZE markers
    smap = dict(act)
    for k, v in ev.get("glob", {}).items():
        if not k.startswith("SIZE "):
            smap[k] = v
    kind = ev["kind"]
    # candidate signing seconds: created_at / sent_at of the ACT map
    cands = []
    for f in ("created_at", "sent_at"):
        if f in smap:
            cands.append(sec_of(smap[f]))
    sec = cands[0] if cands else None
    nonce12 = bytes.fromhex(blob["nonce12_hex"])
    cert40 = blob["cert40"].encode()
    row = {
        "n": i + 1, "kind": kind, "tid": ev["tid"], "t_begin": ev["t_begin"],
        "act_size": len(act), "glob": ev["glob"],
        "blob_hex": ev["blob_hex"], "tag_ok": blob["tag_ok"],
        "cert40": blob["cert40"], "cert40_is_hanaf": blob["cert40"] == HANAF_CERT,
        "nonce12": blob["nonce12_hex"], "device_H": blob["H"],
        "record": blob["record"], "sec_created_at": sec,
        "header_matches_created_sec": any(ap.make_header(c) == blob["blob"][:16] for c in cands),
    }
    # pure verification: H-law + full re-sign
    if sec is not None:
        claims = ap.build_claims(kind, smap, client_sdk=CLIENT_SDK,
                                 include_block2=True)
        H_ours = ap.commitment_digest(claims, nonce12, cert40)
        row["claims_hex"] = claims.hex().upper()
        row["H_ours_matches"] = H_ours.hex().upper() == blob["H"]
        resign = ap.sign(sec, nonce12, claims, cert40)
        row["resign_matches_blob"] = resign == blob["blob"]
        if resign != blob["blob"]:
            fd = next((j for j in range(304) if resign[j] != blob["blob"][j]), None)
            row["resign_first_diff"] = fd
    out_rows.append(row)

json.dump(out_rows, open(os.path.join(HERE, "soverify_hook_parsed.json"), "w"),
          indent=1)

for r in out_rows:
    print("SIGN#%d %-11s tid=%s act=%d glob=%s" % (r["n"], r["kind"], r["tid"], r["act_size"], r["glob"]))
    print("   tag_ok=%s cert40_hanaf=%s header@created_sec=%s" % (r["tag_ok"], r["cert40_is_hanaf"], r.get("header_matches_created_sec")))
    print("   nonce12=%s" % r["nonce12"])
    print("   H_ours_matches=%s resign_byte_exact=%s%s" % (
        r.get("H_ours_matches"), r.get("resign_matches_blob"),
        ("  first_diff=%s" % r["resign_first_diff"]) if r.get("resign_first_diff") is not None else ""))
