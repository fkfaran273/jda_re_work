"""Debug: robust re-parse of NSIGN maps; print claims; try variants."""
import datetime as dt
import json
import re
import sys

ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
sys.path.insert(0, ADJ7)
sys.path.insert(0, ADJ7 + r"\oracle")
import adj7_pure as ap
from adj7_oracle import cbc_decrypt

LOGS = [ADJ7 + r"\work\modules_fresh.txt",
        ADJ7 + r"\work\lsposed_modules.log",
        ADJ7 + r"\work\oracle_logcat.txt"]

blocks = {}
for LOG in LOGS:
    cur = None
    for ln in open(LOG, encoding="utf-8", errors="replace"):
        m = re.search(r"ADJ7ORACLE: SIGN#(\d+) BEGIN", ln)
        if m:
            cur = int(m.group(1))
            blocks.setdefault(cur, {"n": cur, "nsign_map": None, "blob": None,
                                    "arg2": {}})
            continue
        if cur is None:
            continue
        m = re.search(r"ADJ7ORACLE: NSIGN nSign arglens=(\S*),(\{.*\}),B32,31", ln)
        if m and blocks[cur]["nsign_map"] is None:
            blocks[cur]["nsign_map"] = m.group(2)[1:-1]  # strip outer { }
            continue
        m = re.search(r"ADJ7ORACLE: NSIGN nSign blob_hex \[\d/\d\] ([0-9a-f]{608})", ln)
        if m and blocks[cur]["blob"] is None:
            blocks[cur]["blob"] = m.group(1)
            continue
        m = re.search(r"ADJ7ORACLE: SIGN#(\d+) ARG2(_AFTER)? entries=\d+ \[\d/\d\] (.+)$", ln)
        if m:
            b = int(m.group(1))
            for kv in m.group(3).split(" | "):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    blocks.setdefault(b, {"nsign_map": None, "blob": None,
                                          "arg2": {}, "n": b})["arg2"][k] = v


def parse_java_map(s):
    out = {}
    for p in re.split(r", (?=[a-z_][a-z_0-9]*=)", s):
        k, v = p.split("=", 1)
        out[k] = v
    return out


SPLIT = ap.CLAIM_POOL.index("session_count")


def claims_str(m, kind, sdk, with_language=None):
    parts = [str(m[k]) for k in ap.CLAIM_POOL[:SPLIT] if m.get(k) not in (None, "")]
    parts.append(ap.ADJ_SIGNING_ID)
    parts += [str(m[k]) for k in ap.CLAIM_POOL[SPLIT:-2] if m.get(k) not in (None, "")]
    if with_language:
        parts.append(with_language)
    parts += [str(m.get("activity_kind", kind) or ""),
              str(m.get("client_sdk", sdk) or "")]
    return "".join(parts)


results = {}
for n, b in sorted(blocks.items()):
    kind = b["arg2"].get("activity_kind", "?")
    sdk = b["arg2"].get("client_sdk", "")
    if not b["nsign_map"] or not b["blob"]:
        print("SIGN#%d %-11s incomplete (map=%s blob=%s)"
              % (n, kind, bool(b["nsign_map"]), bool(b["blob"])))
        continue
    nmap = parse_java_map(b["nsign_map"])
    blob = bytes.fromhex(b["blob"])
    body = cbc_decrypt(blob[16:272], blob[:16])
    rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
    H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
    cert40 = re.search(r'"c": "([^"]*)"', rec).group(1)
    d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
    a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
    nonce12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
    print("=" * 100)
    print("SIGN#%d %-11s parsed keys=%d" % (n, kind, len(nmap)))
    pk = [k for k in ap.CLAIM_POOL if nmap.get(k) not in (None, "")]
    print("   pool keys(%d): %s" % (len(pk), ",".join(pk)))
    print("   non-pool keys: %s" % ",".join(sorted(set(nmap) - set(ap.CLAIM_POOL))))
    cl = claims_str(nmap, kind, sdk)
    Hc = ap.commitment_digest(cl.encode("latin1"), nonce12, cert40.encode()).hex().upper()
    print("   claims = %r" % cl)
    print("   device H = %s" % H)
    print("   calc   H = %s  %s" % (Hc, "MATCH" if Hc == H else "NO"))
    # variant: insert language at pool position (after idfv... pool index of language?)
    lang_pos = None
    variants = {}
    if "language" not in pk:
        cl2 = claims_str(nmap, kind, sdk, with_language="en")
        Hc2 = ap.commitment_digest(cl2.encode("latin1"), nonce12, cert40.encode()).hex().upper()
        variants["claims+language(en)"] = (cl2, Hc2)
        print("   +language(en) H = %s  %s" % (Hc2, "MATCH" if Hc2 == H else "NO"))
    results[n] = {"kind": kind, "nmap": nmap, "H": H, "nonce12": nonce12.hex(),
                  "cert40": cert40, "claims": cl, "H_calc": Hc,
                  "match": Hc == H}

json.dump(results, open(ADJ7 + r"\work\eb_audit\hook_truth2.json", "w"), indent=1)
print("saved hook_truth2.json")
