#!/usr/bin/env python
# verify_authz.py - from-scratch audit of the adj9 Authorization header.
#
# Works ONLY from raw captures:
#   * device/adj9_wh4.log   : nsign(blob+nano_out) + authorization_header(signature)
#   * rev/attrq2.txt        : real app HTTP requests (UTF-16LE)
#   * rev/mint_pipeline.py  : our auth_header()  (reference, imported)
#   * rev/adj9_full_chain.py: our _auth_header() (reference, imported)
#
# Establishes the EXACT deterministic relation between the 192-byte adj9 blob
# and the signature="..." base64 value, tests competing hypotheses, and checks
# whether OUR Python emits that exact rule.
import base64, hashlib, hmac, re, struct, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "..", "device", "adj9_wh4.log")
ATTRQ2 = os.path.join(HERE, "attrq2.txt")

def read_log():
    with open(LOG, "r", encoding="utf-8", errors="replace") as f:
        return f.read().split("\n")

def parse_record(lines, i):
    """Parse one ###ADJ9_BEGIN..###ADJ9_END record into a field dict."""
    rec = {"line": i + 1}
    j = i
    while j < len(lines) and "ADJ9_END" not in lines[j]:
        t = lines[j]
        if t.startswith("text: "): rec.setdefault("text", []).append(t[6:])
        if t.startswith("hex: "):  rec.setdefault("hex", []).append(t[5:])
        if t.startswith("hex="):    rec["blob_hex"] = t[4:]
        if t.startswith("key2_hex="): rec["key2_hex"] = t[9:]
        if t.startswith("nano_out="): rec["nano_out"] = int(t.split("=")[1])
        j += 1
    return rec

def extract_pairs(lines):
    """Pair every nsign record with the authorization_header that follows it."""
    nsign_idx = [i for i, l in enumerate(lines) if "type=nsign " in l]
    auth_idx = [i for i, l in enumerate(lines) if "type=authorization_header" in l]
    pairs = []
    for a in auth_idx:
        prev = [n for n in nsign_idx if n < a]
        if not prev:
            continue
        n = prev[-1]
        rn, ra = parse_record(lines, n), parse_record(lines, a)
        m = re.search(r'signature="([^"]+)"', ra["text"][0])
        if not m or "blob_hex" not in rn:
            continue
        pairs.append({
            "nsign_line": rn["line"], "auth_line": ra["line"],
            "blob": bytes.fromhex(rn["blob_hex"]),
            "nano_out": rn.get("nano_out"),
            "sig": m.group(1),
            "header_text": ra["text"][0],
        })
    return pairs

# ---------------------------------------------------------------------------
# Candidate derivations signature = b64( DERIV(blob, nano_out) )
# ---------------------------------------------------------------------------
def cand_b64_blob(blob, nano, second):            return base64.b64encode(blob)
def cand_b64_blob_nano(blob, nano, second):       return base64.b64encode(blob + struct.pack(">q", nano))
def cand_b64_blob_rev(blob, nano, second):        return base64.b64encode(blob[::-1])
def cand_b64_hmac_hdr(blob, nano, second):        # HMAC-SHA256 keyed by 16B header
    return base64.b64encode(hmac.new(blob[:16], blob, hashlib.sha256).digest())
def cand_b64_hmac_nano(blob, nano, second):       # HMAC-SHA256 keyed by nano
    return base64.b64encode(hmac.new(struct.pack(">q", nano), blob, hashlib.sha256).digest())
def cand_sha256(blob, nano, second):              return hashlib.sha256(blob).digest()
def cand_b64_sha256(blob, nano, second):          return base64.b64encode(hashlib.sha256(blob).digest())
def cand_b64_blob_1_16(blob, nano, second):       # header only
    return base64.b64encode(blob[:16])
def cand_b64_blob_16_192(blob, nano, second):     # body only
    return base64.b64encode(blob[16:])

CANDS = [
    ("base64(blob)                     [SIGNATURE]", cand_b64_blob),
    ("base64(blob + be64(nano_out))",               cand_b64_blob_nano),
    ("base64(reverse(blob))",                       cand_b64_blob_rev),
    ("base64(HMAC_SHA256(key=blob[:16], msg=blob))",cand_b64_hmac_hdr),
    ("base64(HMAC_SHA256(key=be64(nano), msg=blob))",cand_b64_hmac_nano),
    ("SHA256(blob) raw",                            cand_sha256),
    ("base64(SHA256(blob))",                        cand_b64_sha256),
    ("base64(blob[:16])  header-only",              cand_b64_blob_1_16),
    ("base64(blob[16:])  body-only",                cand_b64_blob_16_192),
]

def test_derivations(pairs):
    print("=== DERIVATION TESTS over %d raw (blob, signature) pairs ===" % len(pairs))
    winners = []
    for name, fn in CANDS:
        ok = 0
        for p in pairs:
            try:
                if fn(p["blob"], p.get("nano_out"), p.get("second")) == p["sig"].encode():
                    ok += 1
            except Exception:
                pass
        tag = "REPRODUCES ALL" if ok == len(pairs) and pairs else ""
        print("  %-45s %d/%d  %s" % (name, ok, len(pairs), tag))
        if ok == len(pairs) and pairs:
            winners.append(name)
    return winners

def check_our_impl(pairs):
    print("\n=== OUR PYTHON IMPLEMENTATION ===")
    # import our production builders
    try:
        sys.path.insert(0, HERE)
        import mint_pipeline
        ours = mint_pipeline.auth_header
        print("mint_pipeline.auth_header  : imported")
    except Exception as e:
        ours = None
        print("mint_pipeline.auth_header  : import FAILED (%s)" % e)
    # verify against every real header, field-for-field
    if ours:
        mism = 0
        for p in pairs:
            got = ours(p["blob"])
            if got != p["header_text"]:
                mism += 1
        print("  mint_pipeline.auth_header reproduces %d/%d real headers exactly"
              % (len(pairs) - mism, len(pairs)))
        # and the derivation itself
        same_rule = all(base64.b64encode(p["blob"]).decode() == p["sig"] for p in pairs)
        print("  uses exactly base64(blob)? %s" % same_rule)
    # functionally check adj9_full_chain._auth_header against every real header
    try:
        import adj9_full_chain
        mism2 = 0
        for p in pairs:
            if adj9_full_chain._auth_header(p["blob"]) != p["header_text"]:
                mism2 += 1
        print("adj9_full_chain._auth_header reproduces %d/%d real headers exactly"
              % (len(pairs) - mism2, len(pairs)))
    except Exception as e:
        print("adj9_full_chain._auth_header: check FAILED (%s)" % e)

def check_attrq2():
    print("\n=== REAL APP REQUESTS (rev/attrq2.txt) ===")
    with open(ATTRQ2, "rb") as f:
        raw = f.read()
    txt = raw.decode("utf-16", errors="replace") if raw[:2] == b"\xff\xfe" else raw.decode("utf-8", "replace")
    sigs = re.findall(r'signature="([^"]+)"', txt)
    lens = set()
    for s in sigs:
        lens.add(len(base64.b64decode(s)))
    print("  Authorization headers      : %d" % len(sigs))
    print("  base64(sig) decodes to     : %s bytes (expect {192})" % lens)
    for field in ("headers_id", "adj_verification", "adj_signing_id", "algorithm", "native_version"):
        vals = set(re.findall(field + r'="([^"]*)"', txt))
        print("  %-24s : %s" % (field, vals))

def check_header_order(pairs):
    print("\n=== AUTHORIZATION HEADER FIELD ORDER (raw bytes) ===")
    p = pairs[0]
    print("  real :", p["header_text"][:100] + "...")
    order = re.findall(r'(\w+)=', p["header_text"])
    print("  order:", order)
    # our order
    print("  ours :", "signature, adj_signing_id, algorithm, headers_id, native_version, adj_verification")

def main():
    lines = read_log()
    pairs = extract_pairs(lines)
    print("=== RAW PAIR EXTRACTION ===")
    for p in pairs:
        print("  nsign@line %-6d auth@line %-6d blob=%dB nano_out=%s"
              % (p["nsign_line"], p["auth_line"], len(p["blob"]), p.get("nano_out")))
    print("  total pairs: %d" % len(pairs))
    winners = test_derivations(pairs)
    print("\n  WINNING RULE(S): %s" % (winners or "NONE"))
    check_our_impl(pairs)
    check_attrq2()
    check_header_order(pairs)
    print("\n=== canonical records (context) ===")
    for i, l in enumerate(lines):
        if "type=canonical" in l:
            nxt = lines[i+1] if i+1 < len(lines) else ""
            pre = nxt[6:40] if nxt.startswith("text: ") else ""
            print("  line %-6d %s" % (i+1, pre))

if __name__ == "__main__":
    main()
