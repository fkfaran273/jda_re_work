# -*- coding: utf-8 -*-
"""make_gold.py -- carve the captures, derive (second, nonce12) per blob,
assert the full byte-exact mint, freeze gold_vectors.json.

Independence rule: nothing is read from prior frozen artifacts.  For every
signed request in the capture:

  1. carve params / Client-Sdk / Authorization sig from the raw .saz
  2. tag law              HMAC(DK37, blob[16:272]) == blob[272:]
  3. record               cbc_decrypt -> RECORD_RE, cert40 = "0"*40,
                         0x10*16 tail; nonce12 recovered from the record
  4. header               brute-force the unix second in
                         [sent_at - 120 s, wire_time + 30 s] with MINSTD;
                         require exactly ONE hit
  5. claims               pool law over the wire map (+ kind, client_sdk)
                         reproduces the record's "b"
  6. byte-exact           sign(second, nonce12, claims) == the captured blob

Only vectors passing 2..6 are frozen.  kind for /sdk_info is probed (info).
"""
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj7ios_pure as sg                                   # noqa: E402

CAPTURES = [
    ("watsons", r"C:\Users\Apps\Downloads\ct_Watson_logs_18Aug_ios.saz"),
    ("nirio", r"C:\Users\Apps\Downloads\nirioiosauto_08Sep_ios_CT.saz"),
]

KIND_MAP = {"session": "session", "sdk_click": "click",
            "attribution": "attribution", "event": "event",
            "third_party_sharing": "third_party_sharing"}
INFO_CANDIDATES = ["info", "sdk_info", "session", "click", "attribution",
                   "third_party_sharing", "push", "unknown", ""]


# ------------------------------------------------------------------ carve
def parse_request(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    method, url = lines[0].split(" ")[0], lines[0].split(" ")[1]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, url, headers, body


def to_epoch(stamp):
    """2026-08-18T09:22:14.702Z+0400 / +05:30 / 7-digit frac -> epoch."""
    import calendar
    m = re.match(r"(.*?)Z?([+-]\d{2}:?\d{2})?$", stamp)
    base, tz = m.group(1), (m.group(2) or "+0000").replace(":", "")
    fm = re.match(r"^(.*\.\d+)", base)
    if fm:
        pre, frac = fm.group(1).rsplit(".", 1)
        if len(frac) != 6:
            base = pre + "." + frac[:6].ljust(6, "0")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            d = datetime.strptime(base, fmt)
            break
        except ValueError:
            continue
    else:
        return None
    d -= timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * (
        1 if tz[0] == "+" else -1)
    return calendar.timegm(d.timetuple()) + d.microsecond / 1e6


def carve(saz_path):
    import urllib.parse as up
    out = []
    zf = zipfile.ZipFile(saz_path)
    names = sorted(n for n in zf.namelist()
                   if re.match(r"raw/\d+_c\.txt$", n.replace("\\", "/")))
    for n in names:
        raw = zf.read(n)
        if b"Signature signature=" not in raw:
            continue
        sid = re.search(r"(\d+)_c", n).group(1)
        method, url, headers, body = parse_request(raw)
        auth = headers.get("authorization", "")
        msig = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
        if not msig:
            continue
        params = {}
        if method == "POST":
            params = dict(up.parse_qsl(body.decode("latin1"),
                                       keep_blank_values=True))
        if "?" in url:
            params.update(dict(up.parse_qsl(url.split("?", 1)[1],
                                            keep_blank_values=True)))
        wire = None
        try:
            mx = zf.read(n.replace("_c.txt", "_m.xml")).decode("utf-8",
                                                               "replace")
            mw = re.search(r'ClientBeginRequest="([^"]+)"', mx)
            if mw:
                wire = to_epoch(mw.group(1))
        except KeyError:
            pass
        out.append({
            "sid": sid, "method": method, "url": url,
            "endpoint": url.split("?")[0].rsplit("/", 1)[-1],
            "params": params, "client_sdk": headers.get("client-sdk", ""),
            "ua": headers.get("user-agent", ""), "sig": msig.group(1),
            "auth_kv": dict(re.findall(r'(\w+)="([^"]*)"', auth)),
            "sent_at": params.get("sent_at") or params.get("created_at"),
            "wire_epoch": wire,
        })
    return out


# ------------------------------------------------------------------ build
def derive_vector(rec):
    blob = bytes.fromhex(rec["sig"])
    assert len(blob) == 304, "blob %d B" % len(blob)
    assert sg.verify_tag(blob), "tag law"
    plain = sg.cbc_decrypt(blob[16:272], blob[:16])
    m = re.match(sg.RECORD_RE, plain)
    assert m and plain.endswith(b"\x10" * 16), "record law"
    assert m.group(3) == sg.CERT40_IOS, "cert40"
    nonce12 = (int(m.group(1).decode().strip()).to_bytes(8, "little")
               + bytes.fromhex(m.group(4).decode()))
    rec_h = m.group(2).decode()

    sent = to_epoch(rec["sent_at"]) if rec["sent_at"] else None
    lo = int((sent if sent else rec["wire_epoch"]) - 120)
    hi = int((rec["wire_epoch"] or sent) + 30)
    secs = [s for s in range(lo, hi + 1) if sg.make_header(s) == blob[:16]]
    assert len(secs) == 1, "header seconds %s" % secs
    second = secs[0]

    if rec["endpoint"] in KIND_MAP:
        kinds = [KIND_MAP[rec["endpoint"]]]
    else:
        kinds = INFO_CANDIDATES
    for kind in kinds:
        claims = sg.build_claims(kind, rec["params"],
                                 client_sdk=rec["client_sdk"])
        if sg.commitment_digest(claims, nonce12).hex().upper() == rec_h:
            break
    else:
        raise AssertionError("claims law: no kind fits %s" % rec["endpoint"])

    minted = sg.sign(second, nonce12, claims)
    assert minted.hex().upper() == rec["sig"], "byte-exact mint"

    return {
        "capture": None,            # filled by caller
        "sid": rec["sid"], "endpoint": rec["endpoint"], "kind": kind,
        "client_sdk": rec["client_sdk"], "params": rec["params"],
        "second": second, "nonce12": nonce12.hex(), "sig": rec["sig"],
        "sent_at": rec["sent_at"], "wire_epoch": rec["wire_epoch"],
        "auth_kv": rec["auth_kv"],
    }


def main():
    vectors = []
    for name, path in CAPTURES:
        path = os.path.abspath(path)
        print("== carving", name, path)
        recs = carve(path)
        print("   %d signed requests" % len(recs))
        for rec in recs:
            v = derive_vector(rec)
            v["capture"] = name
            vectors.append(v)
            print("   sid %-3s %-20s kind=%-20s sec=%d  BYTE-EXACT"
                  % (v["sid"], v["endpoint"], v["kind"], v["second"]))
    out = os.path.join(HERE, "gold_vectors.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=1)
    print("\nfroze %d vectors -> %s" % (len(vectors), out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
