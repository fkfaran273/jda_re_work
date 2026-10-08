"""adj7_oracle.py -- mitmproxy addon: the ADJ7 device-oracle.

The phone (real install: click the link, install from Play, open the app)
routes through this proxy.  Every app.adjust.com request that carries a
Signature Authorization is:

  1. logged with its ORIGINAL signature (the device's own blob);
  2. re-signed with OUR pure-Python signer (adj7_pure) over the SAME
     percent-decoded wire fields -- the Authorization header is replaced;
  3. answered by the real server.

The verdict test: if the install books NON-ORGANIC through our signature,
the signer is proven on a real device install (the adj9 oracle standard).

The offline proof (per request): the device's blob is decrypted with the
universal AES seed, its record's H commitment + nonce12 + cert40 are
recovered, and H is recomputed over OUR claims for the same fields.
CLAIMS_MATCH=True means our claims string == the device's claims string
byte-for-byte (H binds the claims).  CLAIMS_MATCH=False pinpoints the
signing-value bug exactly (the adj9 poisoned-values lesson).

Run:
  python -m mitmproxy_tools_dump -s adj7_oracle.py   (see run_oracle.py)
or the packaged helper in this folder.  Phone: WiFi proxy -> PC:8888,
install the CA from http://mitm.it, then click the link + install + open.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ADJ7 = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ADJ7)

import adj7_pure as ap  # noqa: E402

# per-app campaigns: picked by the request's app_token so one proxy
# serves any adj7 app
CAMPAIGNS = {
    "smxi7gqwu39c": {
        "package_name": "in.hanafintech", "app_version": "3.0.4",
        "app_token": "smxi7gqwu39c", "client_sdk": "android5.6.0",
        "cert_sha1": "c1bfafcaffb84b805288b985fbe48e7f33d2c6df",
        "adj_signing_id": "1300000", "algorithm": "adj7",
        "headers_id": "8", "native_version": "3.62.0",
    },
    "vf3lochhmgw0": {
        "package_name": "social.hunch.app", "app_version": "3.2.33",
        "app_token": "vf3lochhmgw0", "client_sdk": "flutter5.5.0@android5.5.0",
        "cert_sha1": "aa92a18790f85d4e9b5199c7792c55f2fb0f61e1",
        "adj_signing_id": "1300000", "algorithm": "adj7",
        "headers_id": "8", "native_version": "3.62.0",
    },
    "tczjrkpa8lc0": {
        "package_name": "com.burgerizzr.app", "app_version": "2.2.1",
        "app_token": "tczjrkpa8lc0", "client_sdk": "android5.6.0",
        "cert_sha1": "f963db904a1b64d0e75f2b063412f7c5a13c8d1e",
        "adj_signing_id": "1300000", "algorithm": "adj7",
        "headers_id": "8", "native_version": "3.62.0",
    },
}
CAMPAIGN = CAMPAIGNS["smxi7gqwu39c"]

LOG = os.path.join(HERE, "oracle_log.jsonl")
KINDS = {"/session": "session", "/sdk_click": "click", "/event": "event",
         "/attribution": "attribution"}

# ---- the inverse SPN (decrypt the device's blob) -----------------------------
INV_SBOX = [0] * 256
for _v, _s in enumerate(ap.AES_SBOX):
    INV_SBOX[_s] = _v

_INV_MCM = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def _inv_shift_rows(b):
    """inverse of the measured 0x1168 law: new M[r][c] = old M[(r+c)%4][c]"""
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
        out += bytes(a ^ b for a, b in
                     zip(_unspn_chunk(c, ap._RK), prev))
        prev = c
    return out


def parse_device_blob(auth):
    """-> dict with the device's record fields, or None."""
    m = re.search(r'signature="([A-Fa-f0-9]+)"', auth or "")
    if not m:
        return None
    blob = bytes.fromhex(m.group(1))
    if len(blob) != 304:
        return {"error": "blob %d B (not 304)" % len(blob), "blob": blob}
    ok = ap.verify_tag(blob)
    body = cbc_decrypt(blob[16:272], blob[:16])
    rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
    f = {}
    mm = re.search(r'"a":\s*(\d+)', rec)
    if mm:
        f["nonce_a"] = mm.group(1)
    mm = re.search(r'"b":\s*"([0-9A-F]{64})"', rec)
    if mm:
        f["device_H"] = mm.group(1)
    mm = re.search(r'"c":\s*"([0-9A-F]{40})"', rec)
    if mm:
        f["device_cert40"] = mm.group(1)
    mm = re.search(r'"d":\s*"([0-9A-F]{8})"', rec)
    if mm:
        f["device_d8"] = mm.group(1)
    # nonce12 from the record: a = u64le(nonce[0:8]) (20-char right-justified),
    # d = hex-upper of nonce[8:12]
    nonce12 = None
    if "nonce_a" in f and "device_d8" in f:
        a = int(f["nonce_a"])
        lo = a.to_bytes(8, "little")
        d8 = bytes.fromhex(f["device_d8"])
        nonce12 = lo + d8
    f["tag_ok"] = ok
    f["nonce12"] = nonce12.hex() if nonce12 else None
    return f


# ---- the mitmproxy addon ------------------------------------------------------
def _log(rec):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, default=str) + "\n")
    print("[oracle] %s %s -> our-sig=%s claims_match=%s"
          % (rec.get("kind"), rec.get("path"), rec.get("resigned"),
             rec.get("claims_match")))


def _sec_of(fields):
    """The signing second: the device signs at its created_at second
    (proven: blob header == make_header(created_at second) on all four
    golden requests).  Fall back to sent_at, then to proxy-now."""
    import datetime as _dt
    for k in ("created_at", "sent_at"):
        ts = fields.get(k)
        if not ts:
            continue
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
                     r"\.(\d+)Z([+-])(\d{2})(\d{2})", str(ts))
        if not m:
            continue
        Y, Mo, Dd, h, mi, s, _ms, sg, oh, om = m.groups()
        dt = _dt.datetime(int(Y), int(Mo), int(Dd), int(h), int(mi),
                          int(s), tzinfo=_dt.timezone.utc)
        off = _dt.timedelta(hours=int(oh), minutes=int(om))
        return int((dt - off if sg == "+" else dt + off).timestamp())
    return int(time.time())


class Adj7Oracle:
    def request(self, flow):
        host = flow.request.pretty_host
        if "app.adjust.com" not in host:
            return
        path = flow.request.path.split("?")[0]
        kind = KINDS.get(path)
        orig_auth = flow.request.headers.get("Authorization", "")
        if kind is None or "signature=" not in orig_auth.lower():
            rec = {"t": time.time(), "path": path, "kind": kind,
                   "resigned": False, "orig_auth": orig_auth[:80]}
            if kind is not None:
                rec["note"] = "no Signature in Authorization"
                _log(rec)
            return

        # the wire map, percent-decoded (the signed map)
        if flow.request.method == "GET":
            pairs = urllib.parse.parse_qsl(
                flow.request.query.string if hasattr(flow.request.query, "string")
                else flow.request.path.split("?", 1)[-1],
                keep_blank_values=True)
        else:
            raw = flow.request.get_text(strict=False) or ""
            pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True)
        fields = dict(pairs)

        # 1. the device's own blob: decrypt, recover its record
        dev = parse_device_blob(orig_auth)

        # 2. our signature over the same fields, at the device's own second.
        #    client_sdk for the claims comes from the request's Client-SDK
        #    header (flutter5.5.0@android5.5.0 / android5.6.0 -- proven on
        #    hunch + hanafintech).  The NATIVE android SDK additionally signs
        #    its OS language on the attribution (its map carries it even
        #    though the wire GET omits it); the Flutter SDK does not.
        sdk_hdr = (flow.request.headers.get("Client-SDK")
                   or flow.request.headers.get("client-sdk")
                   or CAMPAIGN["client_sdk"])
        sec = _sec_of(fields)
        CAMPAIGN = CAMPAIGNS.get(fields.get("app_token"), CAMPAIGN)
        sfields = dict(fields)
        if kind == "attribution" and "@" not in sdk_hdr:
            sfields.setdefault("language", fields.get("language", "en"))
        claims = ap.build_claims(kind, sfields, client_sdk=sdk_hdr,
                                 include_block2=True)
        cert40 = CAMPAIGN["cert_sha1"].upper().encode()
        nonce12 = os.urandom(12)
        blob = ap.sign(sec, nonce12, claims, cert40)
        auth = ('Signature signature="%s",adj_signing_id="%s",algorithm="%s",'
                'headers_id="%s",native_version="%s"'
                % (blob.hex().upper(), CAMPAIGN["adj_signing_id"],
                   CAMPAIGN["algorithm"], CAMPAIGN["headers_id"],
                   CAMPAIGN["native_version"]))

        # 3. the offline proof: our H over OUR claims vs the device's H
        claims_match = None
        if dev and dev.get("nonce12") and dev.get("device_H"):
            n12 = bytes.fromhex(dev["nonce12"])
            c40 = (dev.get("device_cert40")
                   or CAMPAIGN["cert_sha1"].upper()).encode()
            h_ours = ap.commitment_digest(claims, n12, c40)
            claims_match = (h_ours.hex().upper() == dev["device_H"])

        flow.request.headers["Authorization"] = auth

        _log({"t": time.time(), "path": path, "kind": kind,
              "method": flow.request.method, "fields": fields,
              "resigned": True, "claims_match": claims_match,
              "device_record": dev, "our_second": sec,
              "our_blob": blob.hex().upper(),
              "orig_auth": orig_auth})
        flow.metadata["oracle_claims_match"] = claims_match

    def response(self, flow):
        if "app.adjust.com" not in flow.request.pretty_host:
            return
        path = flow.request.path.split("?")[0]
        body = ""
        if flow.response and flow.response.content:
            body = flow.response.get_text(strict=False)[:800]
        verdict = None
        if path == "/attribution" and body:
            try:
                j = json.loads(body)
                verdict = j.get("attribution", {})
            except Exception:
                pass
        rec = {"t": time.time(), "resp": path, "status": flow.response.status_code
               if flow.response else 0, "body": body, "verdict": verdict}
        if verdict:
            rec["network"] = verdict.get("network")
        _log(rec)


addons = [Adj7Oracle()]
