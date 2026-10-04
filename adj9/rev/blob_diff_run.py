"""blob_diff_run.py — pure byte-diff: genuine app blob vs our Python mint.

Inputs (all from the same capture):
  * the app's 192-B blob            transport_blob.txt  (base64)
  * the app's signing second        recovered from the header law / the log ts
  * the app's sign_input map        transport_capture_log.txt  type=sign_input
  * the app's canonical claims      transport_capture_log.txt  type=canonical

The genuine region (d0/d2/d4) is RECONSTRUCTED from the genuine record's own S
(record[20:24) big-endian = the F.py native seed) so that the region contributes
no free variables: any residual difference is the mint pipeline, not the region.
"""
import base64
import hashlib
import hmac
import itertools
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import F as Fmod
import whiten_decoder as W
import mint_pipeline as MP
import desc10_law
from header_gen import make_header

LOG = os.path.join(HERE, "transport_capture_log.txt")


# ---------------------------------------------------------------------------
# 1. capture-log mining
# ---------------------------------------------------------------------------
def _blocks(path):
    """Yield (type, ts, [text lines]) for every ###ADJ9_BEGIN block."""
    cur = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)", line)
            if m:
                cur = [m.group(1), int(m.group(3)), []]
                continue
            if line.startswith("###ADJ9_END"):
                if cur:
                    yield tuple(cur)
                cur = None
                continue
            if cur is not None:
                cur[2].append(line.rstrip("\n"))


def _text(lines):
    """The whole block body, with the log's literal \\n escapes turned into
    real newlines (the capture writes `text: a\\nb\\n`)."""
    body = "\n".join(lines)
    if body.startswith("text: "):
        body = body[6:]
    return body.replace("\\n", "\n")


def find_genuine(b64):
    """Locate the log blocks belonging to the blob we were handed."""
    sig = 'signature="%s"' % b64
    out = {}
    for typ, ts, lines in _blocks(LOG):
        body = _text(lines)
        if typ == "authorization_header" and sig in body:
            out["auth_ts"] = ts
        if typ == "nsign":
            h = re.search(r"\nhex=([0-9a-f]+)", body)
            if h and base64.b64encode(bytes.fromhex(h.group(1))).decode() == b64:
                out["nsign_ts"] = ts
                out["blob_hex"] = h.group(1)
    ts = out.get("auth_ts")
    if ts is None:
        return None
    # the sign_input / canonical records that bracket this signing
    si = [(t2, ls) for (t, t2, ls) in _blocks(LOG)
          if t == "sign_input" and t2 <= ts + 50]
    if si:
        out["sign_input"] = max(si, key=lambda x: x[0])[1]
    cn = [(t2, ls) for (t, t2, ls) in _blocks(LOG)
          if t == "canonical" and t2 <= ts + 50]
    if cn:
        best = max(cn, key=lambda x: x[0])
        txt = _text(best[1]).strip()
        if txt.startswith("{"):
            out["canonical"] = txt
    return out


def parse_map(txt):
    """`k=v, k=v, ...` to dict (values may contain commas only inside (...) —
    the app's own toString is `key=value` pairs joined by ', ')."""
    d = {}
    for part in txt.split(", "):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        d[k.strip()] = v
    return d


# ---------------------------------------------------------------------------
# 2. region reconstruction from a record (the S-derived, phase-free path)
# ---------------------------------------------------------------------------
def region_from_S(S, head_prefix):
    d4 = Fmod._d4_words(S)
    d0 = Fmod._d0_words(d4, head=head_prefix)
    d2 = int.from_bytes((S & 0xFFFFFFFF).to_bytes(4, "little"), "big")
    return d0, d2, d4


def find_head_prefix(S, head, maxlen=6):
    d4 = Fmod._d4_words(S)
    for L in range(0, maxlen + 1):
        for pre in itertools.product(range(0, 256), repeat=L):
            if W.head_words(Fmod._d0_words(d4, head=pre)) == head:
                return pre
    return None


# ---------------------------------------------------------------------------
# 3. field-wise record diff
# ---------------------------------------------------------------------------
FIELDS = [
    ("magic",            0, 3,   "01 00 08"),
    ("head d0[0..3]",    3, 19,  "d0 words 0..3, rev16 LE-packed"),
    ("flag19",           19, 20, "02"),
    ("S (BE32)",         20, 24, "F.py native seed"),
    ("flag24",           24, 25, "03"),
    ("cert SHA-1 d9",    25, 45, "fad0f10d... (pinned)"),
    ("flag45",           45, 46, "04"),
    ("block32",          46, 78, "32-B hash-like block"),
    ("flag78",           78, 79, "05"),
    ("SHA256(\"\")",      79, 111, "e3b0c442... (pinned)"),
    ("tag111",           111, 114, "06 01 07"),
    ("zeros14",          114, 128, "00*14"),
    ("tail2",            128, 130, "2-B tail"),
    ("ones14",           130, 144, "0e*14"),
]


def field_diff(a, b):
    rows = []
    for name, s, e, note in FIELDS:
        ba, bb = a[s:e], b[s:e]
        rows.append({
            "field": name, "range": "[%d:%d)" % (s, e), "len": e - s,
            "genuine": ba.hex(), "ours": bb.hex(), "equal": ba == bb,
            "note": note,
        })
    return rows


# ---------------------------------------------------------------------------
# 4. law hunt for block32 [46:78) and tail2
# ---------------------------------------------------------------------------
def law_hunt(gen, S, d4, d0, block, tail2, claims, second):
    d4b = b"".join(x.to_bytes(4, "big") for x in d4)
    d0b = b"".join(x.to_bytes(4, "big") for x in d0)
    d2b = struct.pack(">I", d2_of(gen))
    head = gen[3:19]
    seedb = struct.pack(">I", S)
    parts = {
        "head": head, "S": seedb, "d4": d4b, "d0": d0b, "d2": d2b,
        "cert": gen[25:45], "sha0": gen[79:111], "rec": gen,
        "claims": claims.encode("latin1"), "second": struct.pack(">I", second),
        "empty": b"", "zeros14": b"\x00" * 14, "ones14": b"\x0e" * 14,
    }
    names = list(parts)
    hits = []

    # (a) 1..3-part concatenations, SHA-256 (take 32 B) and SHA-1 (+pad)
    for n in (1, 2, 3):
        for combo in itertools.permutations(names, n):
            msg = b"".join(parts[c] for c in combo)
            h = hashlib.sha256(msg).digest()
            if h[:32] == block:
                hits.append(("sha256", combo))
            if h[-32:] == block:
                hits.append(("sha256-tail", combo))
            h1 = hashlib.sha1(msg).digest()
            if (h1 + h1[:12]) == block or (h1 * 2)[:32] == block:
                hits.append(("sha1x2", combo))
            if hashlib.md5(msg).digest() * 2 == block:
                hits.append(("md5x2", combo))
    # (b) HMAC-SHA256 with each part as the key
    for k in names:
        for m in names:
            h = hmac.new(parts[k], parts[m], hashlib.sha256).digest()
            if h == block:
                hits.append(("hmac", (k, m)))
    # (c) hashes of the cert / claims alone
    for n, b in (("cert", parts["cert"]), ("claims", parts["claims"]),
                 ("cert+claims", parts["cert"] + parts["claims"]),
                 ("claims+cert", parts["claims"] + parts["cert"])):
        if hashlib.sha256(b).digest() == block:
            hits.append(("sha256", (n,)))
        if hashlib.sha1(b).digest() * 2 == block[:20] + block[20:]:
            pass
    return hits, parts


def d2_of(rec):
    return int.from_bytes(rec[20:24], "little")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    b64 = open(os.path.join(HERE, "transport_blob.txt")).read().strip()
    gen = base64.b64decode(b64)
    info = find_genuine(b64)
    print("== 1. capture-log extraction ==")
    print("  auth record ts      :", info["auth_ts"])
    print("  nsign record ts     :", info.get("nsign_ts"))
    si_txt = _text(info["sign_input"])
    m = re.search(r"map_toString=\{(.*?)\}\n", si_txt, re.S)
    app_map = parse_map(m.group(1))
    print("  sign_input map keys :", len(app_map))
    canon = info.get("canonical")
    print("  canonical record    :", (canon[:60] + "...") if canon else "MISSING",
          "len=%d" % len(canon) if canon else "")

    # --- 2. second from the header law ---------------------------------------
    print()
    print("== 2. signing second ==")
    second = None
    for s in range(info["auth_ts"] // 1000 - 30, info["auth_ts"] // 1000 + 30):
        if make_header(s) == gen[:16]:
            second = s
            break
    print("  ts %d  ->  second %s  (header law %s)"
          % (info["auth_ts"], second,
             "MATCH" if second else "no match"))

    gd = W.decode_blob(gen)
    grec = gd["record"]
    S = gd["F_seed"]
    head = grec[3:19]
    pre = find_head_prefix(S, head)
    print("  genuine S = %08x   head = %s" % (S, head.hex()))
    print("  head selector prefix recovered:", pre and
          "(%s)" % ", ".join("0x%02x" % x for x in pre))

    # --- 3. the mint --------------------------------------------------------
    print()
    print("== 3. mint with the app's OWN params + second ==")
    our_params = MP.claims_from_wire(app_map, "session")
    d0, d2, d4 = region_from_S(S, pre)
    d0b = b"".join(x.to_bytes(4, "big") for x in d0)
    d2b = d2.to_bytes(4, "big")
    d4b = b"".join(x.to_bytes(4, "big") for x in d4)
    padded, unpadded = MP.claims_for_law(our_params, "session")
    print("  desc10 unpadded %d B  padded %d B" % (unpadded, len(padded)))
    descs, meta = MP.build_descriptors(our_params, "session", d0b, d2b, d4b)
    ours, minfo = MP.finex_mint(descs, second)
    print("  FinEx status=%s steps=%d nrand=%d" %
          (minfo["status"], minfo["steps"], minfo["nrand"]))

    od = W.decode_blob(ours)
    orec = od["record"]

    # --- 4. 192-B word diff -------------------------------------------------
    print()
    print("== 4. the 192-byte diff ==")
    gw = [gen[i:i + 4] for i in range(0, 192, 4)]
    ow = [ours[i:i + 4] for i in range(0, 192, 4)]
    print("  header (words 0-3) match:", gen[:16] == ours[:16])
    diffw = [i for i in range(48) if gw[i] != ow[i]]
    print("  words differing: %d/48  -> %s" % (len(diffw), diffw))
    print("  body words 4-39 (whitened record) differing: %d" %
          len([i for i in diffw if 4 <= i <= 39]))
    print("  words 40-47 (digest tail) differing:      %d" %
          len([i for i in diffw if 40 <= i <= 47]))
    print()
    print("  word  genuine       ours          same")
    for i in range(48):
        tag = "WORD %-2d" % i
        print("  %-6s %s %s %s" % (tag, gw[i].hex(), ow[i].hex(),
                                  "" if gw[i] == ow[i] else "  <-- DIFF"))

    # --- 5. record diff -----------------------------------------------------
    print()
    print("== 5. the 144-B RECORD diff (plaintext plane) ==")
    rows = field_diff(grec, orec)
    for r in rows:
        print("  %-16s %-10s %s" % (r["field"], r["range"],
                                   "SAME" if r["equal"] else "DIFF"))
        if not r["equal"]:
            print("      genuine: %s" % r["genuine"])
            print("      ours   : %s" % r["ours"])
    print("  consts_ok: genuine=%s ours=%s" %
          (gd["consts_ok"], od["consts_ok"]))

    # --- 6. law hunt -------------------------------------------------------
    print()
    print("== 6. law hunt for block32 [46:78) and tail2 ==")
    claims_raw, _ = MP.claims_for_law(our_params, "session")
    hits, parts = law_hunt(grec, S, d4, d0, gd["block"], gd["tail2"],
                           claims_raw.decode("latin1").rstrip("\0"), second)
    print("  combos tried: sha256/sha1x2/md5x2 over 1-3 part perms of %d " % len(parts))
    print("               + HMAC-SHA256 over all key x msg pairs")
    print("  hits:", hits if hits else "NONE")

    # tail2
    t2 = gd["tail2"]
    print("  tail2 genuine = %s ; ours = %s" % (t2.hex(), od["tail2"].hex()))
    cands = {
        "0": b"", "sha0[0:2]": hashlib.sha256(b"").digest()[:2],
        "S[0:2]": parts["S"][:2], "S[-2:]": parts["S"][-2:],
        "d4[0:2]": d4b[:2], "d4[-2:]": d4b[-2:],
        "head[0:2]": head[:2], "head[-2:]": head[-2:],
        "cert[0:2]": grec[25:27],
        "len(S)": struct.pack(">I", 4)[:2],
    }
    for k, v in cands.items():
        if v == t2:
            print("    tail2 MATCH:", k)

    # --- 7. claims comparison ----------------------------------------------
    print()
    print("== 7. claims comparison ==")
    print("  app canonical len  :", len(canon) if canon else "-")
    if canon:
        ours_d10 = build_ours(app_map)
        print("  our build_desc10   : %d B" % len(ours_d10))
        print("  BYTE-EXACT vs app canonical:", ours_d10 == canon)
        if ours_d10 != canon:
            n = min(len(ours_d10), len(canon))
            first = next((i for i in range(n) if ours_d10[i] != canon[i]), n)
            print("  first divergence at byte %d" % first)
            print("    app: ...%s..." % canon[max(0, first - 40):first + 40])
            print("    our: ...%s..." % ours_d10[max(0, first - 40):first + 40])
        # also the wire-order body
        body = open(os.path.join(HERE, "transport", "fp_session_body.txt"),
                    encoding="utf-8").read().strip()
        bp = parse_map(re.sub(r"%([0-9A-Fa-f]{2})",
                              lambda m: chr(int(m.group(1), 16)), body))
        print("  fp_session_body params == app sign_input params:",
              all(bp.get(k) == v for k, v in bp.items() if k in app_map) and
              set(bp) == set(app_map) - {"adj_signing_id", "headers_id",
                                        "native_version", "activity_kind",
                                        "client_sdk", "adj_verification",
                                        "algorithm"})
    return dict(gen=gen, ours=ours, grec=grec, orec=orec, info=info,
                app_map=app_map, canon=canon, second=second, S=S, pre=pre,
                d0=d0, d2=d2, d4=d4, rows=rows, hits=hits, gw=gw, ow=ow,
                diffw=diffw, desc10=(claims_raw, unpadded))


def build_ours(app_map):
    p = MP.claims_from_wire(app_map, "session")
    return desc10_law.build_desc10(p, "session")


if __name__ == "__main__":
    r = main()
    out = {
        "second": r["second"],
        "genuine_blob_hex": r["gen"].hex(),
        "ours_blob_hex": r["ours"].hex(),
        "genuine_record_hex": r["grec"].hex(),
        "ours_record_hex": r["orec"].hex(),
        "header_match": r["gen"][:16] == r["ours"][:16],
        "words_differing": r["diffw"],
        "field_diff": r["rows"],
        "S": "%08x" % r["S"],
        "head_prefix": r["pre"],
        "law_hits": r["hits"],
        "desc10_unpadded": r["desc10"][1],
        "desc10_padded_len": len(r["desc10"][0]),
        "app_canonical": r["canon"],
    }
    json.dump(out, open(os.path.join(HERE, "blob_diff_data.json"), "w"),
              indent=1, ensure_ascii=False)
    print()
    print("wrote blob_diff_data.json")
