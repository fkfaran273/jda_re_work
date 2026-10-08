"""Verify every adj7 request in the dump tail (127..144) against the device H.
Law: claims = build_claims(kind, wire_fields, client_sdk=Client-SDK header,
include_block2=True); attribution (native android only) + language=en.
"""
import datetime as dt
import json
import re
import sys
import urllib.parse

ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
sys.path.insert(0, ADJ7)
sys.path.insert(0, ADJ7 + r"\oracle")
import adj7_pure as ap
from adj7_oracle import parse_device_blob

REQS = json.load(open(ADJ7 + r"\work\eb_audit\requests.json"))

KINDS = {"/session": "session", "/sdk_click": "click", "/event": "event",
         "/attribution": "attribution"}


def sec_of(fields):
    for k in ("created_at", "sent_at"):
        ts = fields.get(k)
        if not ts:
            continue
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
                     r"\.(\d+)Z([+-])(\d{2})(\d{2})", str(ts))
        if not m:
            continue
        Y, Mo, Dd, h, mi, s, _ms, sg, oh, om = m.groups()
        d = dt.datetime(int(Y), int(Mo), int(Dd), int(h), int(mi), int(s),
                        tzinfo=dt.timezone.utc)
        off = dt.timedelta(hours=int(oh), minutes=int(om))
        return int((d - off if sg == "+" else d + off).timestamp())
    return None


def fields_of(r):
    target = r["target"]
    body = bytes.fromhex(r["body"]) if r.get("body") else b""
    if r["method"] == "GET":
        qs = target.split("?", 1)[1] if "?" in target else ""
    else:
        qs = body.decode("latin1", "replace")
    return dict(urllib.parse.parse_qsl(qs, keep_blank_values=True))


def header_second_match(auth, lo, hi):
    """find seconds in [lo,hi] whose make_header == blob[:16]"""
    m = re.search(r'signature="([A-Fa-f0-9]+)"', auth or "")
    if not m:
        return []
    blob = bytes.fromhex(m.group(1))
    if len(blob) != 304:
        return []
    return [s for s in range(lo, hi + 1) if ap.make_header(s) == blob[:16]]


print("%-4s %-12s %-14s %-8s %-6s %-28s %-10s %s"
      % ("idx", "name", "kind", "sdk", "nfld", "app_token/pkg", "cert40[:8]", "H match"))
results = {}
for idx in range(127, 145):
    r = REQS[idx]
    path = r["target"].split("?")[0]
    kind = KINDS.get(path)
    sdk = r["headers"].get("Client-SDK", "")
    auth = r["headers"].get("Authorization", "")
    f = fields_of(r)
    dev = parse_device_blob(auth)
    tag = "n/a"
    verdict = None
    extra = []
    if not dev or not dev.get("device_H"):
        verdict = "BLOB-FAIL:%s" % (dev or {})
    else:
        tag = "OK" if dev.get("tag_ok") else "BADTAG"
        sec = sec_of(f)
        hs = header_second_match(auth, (sec or 0) - 120, (sec or 0) + 120) if sec else []
        sfields = dict(f)
        if kind == "attribution" and "@" not in sdk:
            sfields.setdefault("language", f.get("language", "en"))
        claims = ap.build_claims(kind, sfields, client_sdk=sdk,
                                 include_block2=True)
        n12 = bytes.fromhex(dev["nonce12"])
        c40 = dev.get("device_cert40", "").encode()
        H = ap.commitment_digest(claims, n12, c40).hex().upper()
        verdict = "MATCH" if H == dev["device_H"] else "NO"
        # longest common hex prefix of claims-derived H vs device H is
        # meaningless (hash); but store claims for later diffing
        extra = ["sec=%d hdrsec=%s" % (sec, hs[:2])]
    print("%-4d %-12s %-14s %-8s %-6d %-28s %-10s %-6s %s"
          % (idx, "", kind, sdk[:20], len(f),
             (f.get("app_token", "-") + "/" + f.get("package_name", "-"))[:27],
             (dev.get("device_cert40", "-")[:8] if dev else "-"),
             tag, verdict))
    results[idx] = {"kind": kind, "sdk": sdk, "fields": f, "dev": dev,
                    "verdict": verdict, "second": sec_of(f),
                    "claims_std": (ap.build_claims(
                        kind, (dict(f), sfields)[kind == "attribution" and "@" not in sdk],
                        client_sdk=sdk, include_block2=True).decode("latin1")
                        if dev and dev.get("device_H") else None)}

json.dump(results, open(ADJ7 + r"\work\eb_audit\verify_all.json", "w"), indent=1)
print("\nsaved verify_all.json")
