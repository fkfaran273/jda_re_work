"""Ground-truth test: the LSPosed hook captured the EXACT map passed to the
native nSign AND the native's output blob, for session/click/attribution/event
of the 2026-10-06T13:00 device run (modules_fresh.txt / lsposed_modules.log /
oracle_logcat.txt -- same run).

For each: decrypt blob -> device H/nonce12/cert40; claims = build_claims over
the nSign map; compare H."""
import datetime as dt
import json
import re
import sys

ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
sys.path.insert(0, ADJ7)
sys.path.insert(0, ADJ7 + r"\oracle")
import adj7_pure as ap
from adj7_oracle import parse_device_blob, cbc_decrypt

LOGS = [ADJ7 + r"\work\modules_fresh.txt",
        ADJ7 + r"\work\lsposed_modules.log",
        ADJ7 + r"\work\oracle_logcat.txt"]

blocks = {}   # sign# -> dict
for LOG in LOGS:
    cur = None
    for ln in open(LOG, encoding="utf-8", errors="replace"):
        m = re.search(r"ADJ7ORACLE: SIGN#(\d+) BEGIN", ln)
        if m:
            cur = int(m.group(1))
            blocks.setdefault(cur, {"n": cur, "nsign_map": None, "blob": None,
                                    "arg2": {}, "maps": []})
            continue
        if cur is None:
            continue
        m = re.search(r"ADJ7ORACLE: NSIGN nSign arglens=[^,]*,(\{.*\}),B32,31", ln)
        if m and blocks[cur]["nsign_map"] is None:
            blocks[cur]["nsign_map"] = m.group(1)
            continue
        m = re.search(r"ADJ7ORACLE: NSIGN nSign blob_hex \[\d/\d\] ([0-9a-f]{608})", ln)
        if m and blocks[cur]["blob"] is None:
            blocks[cur]["blob"] = m.group(1)
            continue
        m = re.search(r"ADJ7ORACLE: SIGN#(\d+) ARG2 entries=\d+ \[\d/\d\] (.+)$", ln)
        if m:
            b = int(m.group(1))
            for kv in m.group(2).split(" | "):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    blocks.setdefault(b, {"nsign_map": None, "blob": None,
                                          "arg2": {}, "maps": [], "n": b})["arg2"][k] = v
            continue
        m = re.search(r"ADJ7ORACLE: SIGN#(\d+) END", ln)
        if m:
            cur = None

print("blocks found:", sorted(blocks.keys()))
for n, b in sorted(blocks.items()):
    print("  SIGN#%d kind=%s sdk=%s map=%s blob=%s"
          % (n, b["arg2"].get("activity_kind"), b["arg2"].get("client_sdk"),
             "yes" if b["nsign_map"] else "NO", "yes" if b["blob"] else "NO"))


def parse_java_map(s):
    out = {}
    parts = re.split(r", (?=[a-z_][a-z_0-9]*=)", s)
    for p in parts:
        k, v = p.split("=", 1)
        out[k] = v
    return out


def sec_of_created(ts):
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", ts)
    Y, Mo, Dd, h, mi, s = m.groups()
    d = dt.datetime(int(Y), int(Mo), int(Dd), int(h), int(mi), int(s),
                    tzinfo=dt.timezone.utc)
    return int(d.timestamp()) - 5 * 3600 - 1800  # Z+0530 convention


results = {}
for n, b in sorted(blocks.items()):
    kind = b["arg2"].get("activity_kind", "?")
    sdk = b["arg2"].get("client_sdk", "")
    if not b["nsign_map"] or not b["blob"]:
        print("SIGN#%d incomplete" % n)
        continue
    nmap = parse_java_map(b["nsign_map"])
    blob = bytes.fromhex(b["blob"])
    ok_tag = ap.verify_tag(blob)
    body = cbc_decrypt(blob[16:272], blob[:16])
    rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
    H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
    cert40 = re.search(r'"c": "([^"]*)"', rec).group(1)
    d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
    a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
    nonce12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
    # signing second from header
    c_at = nmap.get("created_at", "")
    base = sec_of_created(c_at) if c_at else 0
    secs = [s for s in range(base - 900, base + 900) if ap.make_header(s) == blob[:16]]
    # claims from the EXACT nSign map
    claims_full = ap.build_claims(kind, nmap, client_sdk=sdk, include_block2=True)
    H_full = ap.commitment_digest(claims_full, nonce12, cert40.encode()).hex().upper()
    # variant: without block2
    claims_nb = ap.build_claims(kind, nmap, client_sdk=sdk, include_block2=False)
    H_nb = ap.commitment_digest(claims_nb, nonce12, cert40.encode()).hex().upper()
    verdict = "MATCH" if H_full == H else ("MATCH-noBlock2" if H_nb == H else "NO")
    print("-" * 100)
    print("SIGN#%d %-11s keys=%d blob-tag=%s sec=%s(created %s)"
          % (n, kind, len(nmap), ok_tag, secs[:1], c_at))
    print("   device H  =", H)
    print("   calc  H   =", H_full, verdict)
    print("   cert40    =", cert40, " nonce12 =", nonce12.hex())
    results[n] = {"kind": kind, "nmap": nmap, "H": H, "H_calc": H_full,
                  "nonce12": nonce12.hex(), "cert40": cert40,
                  "second": secs[0] if secs else None, "verdict": verdict,
                  "claims_full": claims_full.decode("latin1", "replace")}

json.dump(results, open(ADJ7 + r"\work\eb_audit\hook_truth.json", "w"), indent=1)
print("saved hook_truth.json")
